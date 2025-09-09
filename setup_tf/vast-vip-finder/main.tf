# vast-vip-finder/main.tf - Terraform Module for VIP Pool Range Discovery

terraform {
  required_providers {
    vastdata = {
      source  = "vast-data/vastdata"
      version = ">= 2.0.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
  }
}

# Variables
variable "vast_host" {
  description = "VAST Data cluster hostname or IP"
  type        = string
}

variable "vast_port" {
  description = "VAST Data cluster port"
  type        = number
  default     = 443
}

variable "vast_user" {
  description = "VAST Data username"
  type        = string
  sensitive   = true
}

variable "vast_password" {
  description = "VAST Data password"
  type        = string
  sensitive   = true
}

variable "pool_name" {
  description = "Name of the VIP pool to analyze"
  type        = string
  default     = "main"
}

variable "required_consecutive_ips" {
  description = "Number of consecutive IPs required"
  type        = number
  default     = 3
}

variable "max_ranges_to_return" {
  description = "Maximum number of consecutive ranges to return"
  type        = number
  default     = 5
}

# Get target pool for network info
data "vastdata_vip_pool" "target" {
  name = var.pool_name
}

# Get all pools for conflict detection
data "http" "vip_pools" {
  url    = "https://${var.vast_host}:${var.vast_port}/api/v5/vippools/"
  method = "GET"
  request_headers = {
    "Accept"        = "application/json"
    "Authorization" = "Basic ${base64encode("${var.vast_user}:${var.vast_password}")}"
  }
  insecure = true
}

# Core logic (extracted from your main.tf)
locals {
  # Get CIDR from target pool
  subnet_cidr = data.vastdata_vip_pool.target.subnet_cidr
  first_ip    = data.vastdata_vip_pool.target.ip_ranges[0][0]
  
  # Calculate network address using CIDR
  ip_parts  = split(".", local.first_ip)
  ip_as_int = (
    tonumber(local.ip_parts[0]) * 16777216 +
    tonumber(local.ip_parts[1]) * 65536 +
    tonumber(local.ip_parts[2]) * 256 +
    tonumber(local.ip_parts[3])
  )
  
  # Apply subnet mask to get network portion
  host_bits   = 32 - local.subnet_cidr
  network_int = floor(local.ip_as_int / pow(2, local.host_bits)) * pow(2, local.host_bits)
  
  # Convert back to IP
  network_ip = join(".", [
    floor(local.network_int / 16777216),
    floor((local.network_int % 16777216) / 65536),
    floor((local.network_int % 65536) / 256),
    local.network_int % 256
  ])
  
  network_cidr = "${local.network_ip}/${local.subnet_cidr}"
  
  # Calculate scanning parameters
  network_bits           = local.subnet_cidr
  full_network_octets    = floor(local.network_bits / 8)
  remaining_network_bits = local.network_bits % 8
  network_octets         = split(".", local.network_ip)
  
  # Generate scan candidates (your existing logic)
  scan_ips = local.full_network_octets == 4 ? [
    local.network_ip
  ] : local.full_network_octets == 3 ? [
    for d in range(1, min(255, pow(2, local.host_bits))) :
    "${local.network_octets[0]}.${local.network_octets[1]}.${local.network_octets[2]}.${tonumber(local.network_octets[3]) + d}"
  ] : local.full_network_octets == 2 && local.remaining_network_bits > 0 ? flatten([
    for c_offset in range(0, pow(2, 8 - local.remaining_network_bits)) : [
      for d in range(1, 255) :
      "${local.network_octets[0]}.${local.network_octets[1]}.${tonumber(local.network_octets[2]) + c_offset}.${d}"
    ]
  ]) : local.full_network_octets == 2 ? flatten([
    for c in range(0, 256) : [
      for d in range(1, 255) :
      "${local.network_octets[0]}.${local.network_octets[1]}.${c}.${d}"
    ]
  ]) : local.full_network_octets == 1 && local.remaining_network_bits > 0 ? flatten([
    for b_offset in range(0, min(256, pow(2, 8 - local.remaining_network_bits))) : flatten([
      for c in range(0, min(256, 20)) : [
        for d in range(1, 255, 10) :
        "${local.network_octets[0]}.${tonumber(local.network_octets[1]) + b_offset}.${c}.${d}"
      ]
    ])
  ]) : local.full_network_octets == 1 ? flatten([
    for b in range(0, 256, 20) : flatten([
      for c in range(0, 256, 20) : [
        for d in range(1, 255, 10) :
        "${local.network_octets[0]}.${b}.${c}.${d}"
      ]
    ])
  ]) : flatten([
    for a_offset in range(0, min(256, pow(2, max(0, 8 - local.remaining_network_bits)))) : flatten([
      for b in range(0, 256, 50) : flatten([
        for c in range(0, 256, 50) : [
          for d in range(1, 255, 50) :
          "${tonumber(local.network_octets[0]) + a_offset}.${b}.${c}.${d}"
        ]
      ])
    ])
  ])
  
  # Get used IPs from all pools
  all_pools = jsondecode(data.http.vip_pools.response_body)
  used_ips = toset(flatten([
    for pool in local.all_pools : flatten([
      for range_pair in try(pool.ip_ranges, []) : [
        for ip_int in range(
          tonumber(split(".", range_pair[0])[0]) * 16777216 +
          tonumber(split(".", range_pair[0])[1]) * 65536 +
          tonumber(split(".", range_pair[0])[2]) * 256 +
          tonumber(split(".", range_pair[0])[3]),
          tonumber(split(".", range_pair[1])[0]) * 16777216 +
          tonumber(split(".", range_pair[1])[1]) * 65536 +
          tonumber(split(".", range_pair[1])[2]) * 256 +
          tonumber(split(".", range_pair[1])[3]) + 1
        ) : join(".", [
          floor(ip_int / 16777216),
          floor((ip_int % 16777216) / 65536),
          floor((ip_int % 65536) / 256),
          ip_int % 256
        ])
      ]
    ])
  ]))
  
  # Find available IPs
  available_ips = [
    for ip in local.scan_ips : ip
    if !contains(local.used_ips, ip)
  ]
  
  # Find consecutive ranges
  max_possible_ranges = length(local.available_ips) >= var.required_consecutive_ips ? length(local.available_ips) - var.required_consecutive_ips + 1 : 0
  max_ranges_to_check = min(var.max_ranges_to_return, local.max_possible_ranges)
  
  consecutive_ranges = local.max_ranges_to_check > 0 ? [
    for i in range(0, local.max_ranges_to_check) : {
      start_ip = local.available_ips[i]
      end_ip   = local.available_ips[i + var.required_consecutive_ips - 1]
      ips      = slice(local.available_ips, i, i + var.required_consecutive_ips)
    }
  ] : []
}

# Outputs
output "network_info" {
  description = "Network analysis and CIDR information"
  value = {
    pool_name        = var.pool_name
    subnet_cidr      = local.subnet_cidr
    network_cidr     = local.network_cidr
    scanning_scope   = local.full_network_octets == 4 ? "Single IP (/32)" : local.full_network_octets == 3 ? "4th octet only (/24-/31)" : local.full_network_octets == 2 && local.remaining_network_bits > 0 ? "${8 - local.remaining_network_bits} bits of 3rd octet + 4th octet (/17-/23)" : local.full_network_octets == 2 ? "3rd and 4th octets fully (/16)" : local.full_network_octets == 1 && local.remaining_network_bits > 0 ? "${8 - local.remaining_network_bits} bits of 2nd octet + 3rd + 4th (/9-/15)" : local.full_network_octets == 1 ? "2nd, 3rd, 4th octets (/8)" : "Multiple octets (large network)"
    ips_scanned      = length(local.scan_ips)
    ips_used         = length(local.used_ips)
    ips_available    = length(local.available_ips)
  }
}

output "available_ranges" {
  description = "Available consecutive IP ranges"
  value = {
    required_consecutive = var.required_consecutive_ips
    ranges_found        = length(local.consecutive_ranges)
    ranges              = local.consecutive_ranges
    first_available     = length(local.consecutive_ranges) > 0 ? local.consecutive_ranges[0] : null
  }
}

output "raw_data" {
  description = "Raw data for external processing"
  value = {
    all_available_ips = local.available_ips
    all_used_ips     = sort(tolist(local.used_ips))
    network_cidr     = local.network_cidr
  }
}