#!/usr/bin/env bash

# export TF_LOG=TRACE

# Change to the script's directory
cd "$(dirname "$0")"

# Define the Terraform Docker image to use
TERRAFORM_IMAGE="hashicorp/terraform:1.13.0-rc1"

echo "Running Terraform and Research Curation Kafka setup..."

# Run terraform first
echo "================================================"
echo "Step 1: Running Terraform"
echo "================================================"

sudo docker run --rm -it \
  --network host \
  --privileged \
  --add-host host.docker.internal:host-gateway \
  -v "$(pwd):/app" \
  -w "/app" \
  "$TERRAFORM_IMAGE" "$@"

TERRAFORM_EXIT_CODE=$?

if [ $TERRAFORM_EXIT_CODE -ne 0 ]; then
    echo ""
    echo "❌ Terraform failed with exit code: $TERRAFORM_EXIT_CODE"
    exit $TERRAFORM_EXIT_CODE
fi

echo ""
echo "✅ Terraform completed successfully!"

# Check if this was an apply or plan operation
if [[ "$*" == *"apply"* ]] && [ $TERRAFORM_EXIT_CODE -eq 0 ]; then
    echo ""
    echo "================================================"
    echo "Step 2: Creating Research Curation Kafka Topics"
    echo "================================================"
    
    # Check if connection_details.txt exists (created by Terraform)
    if [ ! -f "connection_details.txt" ]; then
        echo "❌ connection_details.txt not found. Terraform may not have completed successfully."
        exit 1
    fi
    
    # Extract Kafka broker IP and topics from connection details
    KAFKA_BROKER=$(grep "^KAFKA_BROKER=" connection_details.txt | cut -d'=' -f2)
    KAFKA_TOPIC_FILE_INGESTED=$(grep "^KAFKA_TOPIC_FILE_INGESTED=" connection_details.txt | cut -d'=' -f2)
    KAFKA_TOPIC_METADATA_EXTRACTED=$(grep "^KAFKA_TOPIC_METADATA_EXTRACTED=" connection_details.txt | cut -d'=' -f2)
    KAFKA_TOPIC_QUALITY_VALIDATED=$(grep "^KAFKA_TOPIC_QUALITY_VALIDATED=" connection_details.txt | cut -d'=' -f2)
    KAFKA_TOPIC_CATALOG_UPDATED=$(grep "^KAFKA_TOPIC_CATALOG_UPDATED=" connection_details.txt | cut -d'=' -f2)
    
    if [ -z "$KAFKA_BROKER" ] || [ -z "$KAFKA_TOPIC_FILE_INGESTED" ] || [ -z "$KAFKA_TOPIC_METADATA_EXTRACTED" ] || [ -z "$KAFKA_TOPIC_QUALITY_VALIDATED" ] || [ -z "$KAFKA_TOPIC_CATALOG_UPDATED" ]; then
        echo "❌ Could not extract Kafka details from connection_details.txt"
        echo "KAFKA_BROKER: $KAFKA_BROKER"
        echo "KAFKA_TOPIC_FILE_INGESTED: $KAFKA_TOPIC_FILE_INGESTED" 
        echo "KAFKA_TOPIC_METADATA_EXTRACTED: $KAFKA_TOPIC_METADATA_EXTRACTED"
        echo "KAFKA_TOPIC_QUALITY_VALIDATED: $KAFKA_TOPIC_QUALITY_VALIDATED"
        echo "KAFKA_TOPIC_CATALOG_UPDATED: $KAFKA_TOPIC_CATALOG_UPDATED"
        exit 1
    fi
    
    echo "📋 Research Curation Kafka Configuration:"
    echo "   Broker: $KAFKA_BROKER"
    echo "   Topics:"
    echo "     • File Ingested: $KAFKA_TOPIC_FILE_INGESTED"
    echo "     • Metadata Extracted: $KAFKA_TOPIC_METADATA_EXTRACTED"
    echo "     • Quality Validated: $KAFKA_TOPIC_QUALITY_VALIDATED"
    echo "     • Catalog Updated: $KAFKA_TOPIC_CATALOG_UPDATED"
    echo ""
    
    # Wait a bit for Kafka to be ready
    echo "⏳ Waiting 30 seconds for Kafka service to initialize..."
    sleep 30
    
    # Test Kafka connectivity
    echo "🔍 Testing Kafka connectivity..."
    if timeout 10 bash -c "echo > /dev/tcp/${KAFKA_BROKER%:*}/${KAFKA_BROKER#*:}" 2>/dev/null; then
        echo "✅ Kafka broker is reachable"
    else
        echo "⚠️  Kafka broker not immediately reachable, but continuing..."
    fi
    
    echo ""
    echo "🚀 Creating Research Curation Kafka topics..."
    
    # Create File Ingested topic
    echo "Creating topic: $KAFKA_TOPIC_FILE_INGESTED"
    docker run --rm --network host jforge/kafka-tools \
      kafka-topics.sh \
      --bootstrap-server "$KAFKA_BROKER" \
      --create \
      --topic "$KAFKA_TOPIC_FILE_INGESTED" \
      --partitions 3 \
      --replication-factor 1 \
      --if-not-exists
    
    # Create Metadata Extracted topic
    echo "Creating topic: $KAFKA_TOPIC_METADATA_EXTRACTED"
    docker run --rm --network host jforge/kafka-tools \
      kafka-topics.sh \
      --bootstrap-server "$KAFKA_BROKER" \
      --create \
      --topic "$KAFKA_TOPIC_METADATA_EXTRACTED" \
      --partitions 3 \
      --replication-factor 1 \
      --if-not-exists
    
    # Create Quality Validated topic
    echo "Creating topic: $KAFKA_TOPIC_QUALITY_VALIDATED"
    docker run --rm --network host jforge/kafka-tools \
      kafka-topics.sh \
      --bootstrap-server "$KAFKA_BROKER" \
      --create \
      --topic "$KAFKA_TOPIC_QUALITY_VALIDATED" \
      --partitions 3 \
      --replication-factor 1 \
      --if-not-exists
    
    # Create Catalog Updated topic
    echo "Creating topic: $KAFKA_TOPIC_CATALOG_UPDATED"
    docker run --rm --network host jforge/kafka-tools \
      kafka-topics.sh \
      --bootstrap-server "$KAFKA_BROKER" \
      --create \
      --topic "$KAFKA_TOPIC_CATALOG_UPDATED" \
      --partitions 3 \
      --replication-factor 1 \
      --if-not-exists
    
    echo ""
    echo "📋 Verifying topics..."
    
    # List all topics
    echo "All topics:"
    docker run --rm --network host jforge/kafka-tools \
      kafka-topics.sh \
      --bootstrap-server "$KAFKA_BROKER" \
      --list
    
    # Describe created topics
    echo ""
    echo "Topic details:"
    docker run --rm --network host jforge/kafka-tools \
      kafka-topics.sh \
      --bootstrap-server "$KAFKA_BROKER" \
      --describe \
      --topic "$KAFKA_TOPIC_FILE_INGESTED" 2>/dev/null || echo "Could not describe $KAFKA_TOPIC_FILE_INGESTED"
    
    docker run --rm --network host jforge/kafka-tools \
      kafka-topics.sh \
      --bootstrap-server "$KAFKA_BROKER" \
      --describe \
      --topic "$KAFKA_TOPIC_METADATA_EXTRACTED" 2>/dev/null || echo "Could not describe $KAFKA_TOPIC_METADATA_EXTRACTED"
    
    docker run --rm --network host jforge/kafka-tools \
      kafka-topics.sh \
      --bootstrap-server "$KAFKA_BROKER" \
      --describe \
      --topic "$KAFKA_TOPIC_QUALITY_VALIDATED" 2>/dev/null || echo "Could not describe $KAFKA_TOPIC_QUALITY_VALIDATED"
    
    docker run --rm --network host jforge/kafka-tools \
      kafka-topics.sh \
      --bootstrap-server "$KAFKA_BROKER" \
      --describe \
      --topic "$KAFKA_TOPIC_CATALOG_UPDATED" 2>/dev/null || echo "Could not describe $KAFKA_TOPIC_CATALOG_UPDATED"
    
    echo ""
    echo "🎉 Research Curation Kafka setup completed!"
    echo ""
    echo "📝 Test your topics with:"
    echo "docker run --rm -it --network host jforge/kafka-tools kafka-console-producer.sh --bootstrap-server $KAFKA_BROKER --topic $KAFKA_TOPIC_FILE_INGESTED"
    echo "docker run --rm -it --network host jforge/kafka-tools kafka-console-producer.sh --bootstrap-server $KAFKA_BROKER --topic $KAFKA_TOPIC_METADATA_EXTRACTED"
    echo ""
    
elif [[ "$*" == *"destroy"* ]] && [ $TERRAFORM_EXIT_CODE -eq 0 ]; then
    echo ""
    echo "🗑️  Infrastructure destroyed successfully"
    
elif [[ "$*" == *"plan"* ]]; then
    echo ""
    echo "📋 Terraform plan completed. Run './tf_cmd.sh apply' to create infrastructure and Research Curation Kafka topics."
    
fi

echo ""
echo "================================================"
echo "Research Curation setup completed successfully!"
echo "================================================"

exit $TERRAFORM_EXIT_CODE