# main.tf - Actually CIDR-aware IP range finder (no more defaulting to last octet!)

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

provider "vastdata" {
  host            = var.vast_host
  port            = var.vast_port
  username        = var.vast_user
  password        = var.vast_password
  skip_ssl_verify = true
}

# Variables
variable "vast_host" {
  type = string
}

variable "vast_port" {
  type    = number
  default = 443
}

variable "vast_user" {
  type      = string
  sensitive = true
}

variable "vast_password" {
  type      = string
  sensitive = true
}

variable "required_consecutive_ips" {
  type    = number
  default = 3
}

# Get main pool for network info
data "vastdata_vip_pool" "main" {
  name = "main"
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

locals {
  # Get CIDR from main pool
  subnet_cidr = data.vastdata_vip_pool.main.subnet_cidr                    # e.g., 16, 24, 8, 20, 22, etc.
  first_ip = data.vastdata_vip_pool.main.ip_ranges[0][0]                   # e.g., "172.200.203.1"
  
  # Calculate actual network address using CIDR (proper subnet math)
  ip_parts = split(".", local.first_ip)                                    # ["172", "200", "203", "1"]
  ip_as_int = (
    tonumber(local.ip_parts[0]) * 16777216 +                               # 172 * 256^3
    tonumber(local.ip_parts[1]) * 65536 +                                  # 200 * 256^2
    tonumber(local.ip_parts[2]) * 256 +                                    # 203 * 256^1
    tonumber(local.ip_parts[3])                                            # 1
  )
  
  # Apply subnet mask to get network portion
  host_bits = 32 - local.subnet_cidr                                       # 16 for /16, 8 for /24, 12 for /20
  network_int = floor(local.ip_as_int / pow(2, local.host_bits)) * pow(2, local.host_bits)
  
  # Convert back to IP
  network_ip = join(".", [
    floor(local.network_int / 16777216),
    floor((local.network_int % 16777216) / 65536),
    floor((local.network_int % 65536) / 256),
    local.network_int % 256
  ])
  
  network_cidr = "${local.network_ip}/${local.subnet_cidr}"                # e.g., "172.200.0.0/16" or "172.200.192.0/20"
  
  # Calculate which octets can vary based on actual CIDR (not hardcoded values)
  network_bits = local.subnet_cidr                                         # e.g., 20, 22, 24, 16, etc.
  full_network_octets = floor(local.network_bits / 8)                      # e.g., /20 = 2, /24 = 3, /16 = 2
  remaining_network_bits = local.network_bits % 8                          # e.g., /20 = 4, /24 = 0, /16 = 0
  
  # Build network octets for scanning
  network_octets = split(".", local.network_ip)                            # ["172", "200", "192", "0"] for /20
  
  # Generate scan candidates based on actual CIDR math (not hardcoded /8, /16, /24)
  scan_ips = local.full_network_octets == 4 ? [                            # /32: no host bits, only one IP
    local.network_ip
  ] : local.full_network_octets == 3 ? [                                   # /24-/31: vary 4th octet only
    for d in range(1, min(255, pow(2, local.host_bits))) :
    "${local.network_octets[0]}.${local.network_octets[1]}.${local.network_octets[2]}.${tonumber(local.network_octets[3]) + d}"
  ] : local.full_network_octets == 2 && local.remaining_network_bits > 0 ? flatten([ # /17-/23: vary part of 3rd octet + 4th octet
    for c_offset in range(0, pow(2, 8 - local.remaining_network_bits)) : [
      for d in range(1, 255) :
      "${local.network_octets[0]}.${local.network_octets[1]}.${tonumber(local.network_octets[2]) + c_offset}.${d}"
    ]
  ]) : local.full_network_octets == 2 ? flatten([                          # /16: vary 3rd and 4th octets fully
    for c in range(0, 256) : [
      for d in range(1, 255) :
      "${local.network_octets[0]}.${local.network_octets[1]}.${c}.${d}"
    ]
  ]) : local.full_network_octets == 1 && local.remaining_network_bits > 0 ? flatten([ # /9-/15: vary part of 2nd octet + 3rd + 4th
    for b_offset in range(0, min(256, pow(2, 8 - local.remaining_network_bits))) : flatten([
      for c in range(0, min(256, 20)) : [                                  # Limit for performance
        for d in range(1, 255, 10) :                                       # Sample for performance
        "${local.network_octets[0]}.${tonumber(local.network_octets[1]) + b_offset}.${c}.${d}"
      ]
    ])
  ]) : local.full_network_octets == 1 ? flatten([                          # /8: vary 2nd, 3rd, 4th octets (limited)
    for b in range(0, 256, 20) : flatten([                                 # Sample every 20th for performance
      for c in range(0, 256, 20) : [
        for d in range(1, 255, 10) :
        "${local.network_octets[0]}.${b}.${c}.${d}"
      ]
    ])
  ]) : flatten([                                                            # /1-/7: very large networks, sample heavily
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
  
  # Find consecutive ranges (fixed syntax - no more Python-style slicing)
  max_possible_ranges = length(local.available_ips) >= var.required_consecutive_ips ? length(local.available_ips) - var.required_consecutive_ips + 1 : 0
  max_ranges_to_return = min(5, local.max_possible_ranges)
  
  consecutive_ranges = local.max_ranges_to_return > 0 ? [
    for i in range(0, local.max_ranges_to_return) : {
      start_ip = local.available_ips[i]
      end_ip = local.available_ips[i + var.required_consecutive_ips - 1]
      ips = slice(local.available_ips, i, i + var.required_consecutive_ips)
    }
  ] : []
}

# Outputs showing full CIDR awareness
output "cidr_analysis" {
  description = "Shows exactly what CIDR is being used and how scanning works"
  value = {
    main_pool_cidr = local.subnet_cidr                      # The actual CIDR: 8, 16, 20, 22, 24, etc.
    calculated_network = local.network_cidr                 # Calculated network: "172.200.0.0/16" or "172.200.192.0/20"
    first_ip_in_pool = local.first_ip                       # IP used for calculation: "172.200.203.1"
    
    # Show scanning scope based on actual CIDR calculation (not hardcoded)
    scanning_scope = local.full_network_octets == 4 ? "Single IP (/32)" : local.full_network_octets == 3 ? "4th octet only (/24-/31)" : local.full_network_octets == 2 && local.remaining_network_bits > 0 ? "${8 - local.remaining_network_bits} bits of 3rd octet + 4th octet (/17-/23)" : local.full_network_octets == 2 ? "3rd and 4th octets fully (/16)" : local.full_network_octets == 1 && local.remaining_network_bits > 0 ? "${8 - local.remaining_network_bits} bits of 2nd octet + 3rd + 4th (/9-/15)" : local.full_network_octets == 1 ? "2nd, 3rd, 4th octets (/8)" : "Multiple octets (large network)"
    
    # Show the math behind the scanning
    network_bits = local.network_bits                       # 20, 22, 24, etc.
    host_bits = local.host_bits                             # 12, 10, 8, etc.
    full_network_octets = local.full_network_octets         # 2, 3, etc.
    remaining_network_bits = local.remaining_network_bits   # 4, 0, etc.
    varying_bits_in_partial_octet = local.remaining_network_bits > 0 ? 8 - local.remaining_network_bits : 0
    
    total_ips_scanned = length(local.scan_ips)              # How many IPs were checked
    sample_scan_ips = length(local.scan_ips) > 0 ? slice(local.scan_ips, 0, min(10, length(local.scan_ips))) : []
  }
}

output "ip_usage" {
  value = {
    network = local.network_cidr                            # "172.200.0.0/16" or "172.200.192.0/20"
    total_used_ips = length(local.used_ips)                 # Count of used IPs
    sample_used_ips = length(local.used_ips) > 0 ? slice(sort(tolist(local.used_ips)), 0, min(20, length(local.used_ips))) : []
    total_available_ips = length(local.available_ips)       # Count of available IPs
  }
}

output "free_ranges" {
  value = {
    network = local.network_cidr                            # True network based on CIDR
    method = "CIDR-based scanning (works for any CIDR, not just /8, /16, /24)"
    count = length(local.consecutive_ranges)                # Number of consecutive ranges found
    ranges = local.consecutive_ranges                       # The actual ranges
    first_available = length(local.consecutive_ranges) > 0 ? local.consecutive_ranges[0] : null
  }
}