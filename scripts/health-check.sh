#!/bin/bash

# Health Check Script for Compliance Sentinel
# This script performs comprehensive health checks on the system

set -euo pipefail

# Configuration
NAMESPACE="${NAMESPACE:-compliance-sentinel}"
TIMEOUT="${TIMEOUT:-30}"
VERBOSE="${VERBOSE:-false}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Health check results
declare -A health_results

# Check Kubernetes cluster connectivity
check_kubernetes() {
    log_info "Checking Kubernetes cluster connectivity..."
    
    if kubectl cluster-info >/dev/null 2>&1; then
        health_results["kubernetes"]="PASS"
        log_success "Kubernetes cluster is accessible"
    else
        health_results["kubernetes"]="FAIL"
        log_error "Cannot connect to Kubernetes cluster"
        return 1
    fi
}

# Check namespace existence
check_namespace() {
    log_info "Checking namespace: $NAMESPACE"
    
    if kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
        health_results["namespace"]="PASS"
        log_success "Namespace $NAMESPACE exists"
    else
        health_results["namespace"]="FAIL"
        log_error "Namespace $NAMESPACE does not exist"
        return 1
    fi
}

# Check deployments
check_deployments() {
    log_info "Checking deployments..."
    
    local deployments=("compliance-sentinel" "compliance-sentinel-worker")
    local all_healthy=true
    
    for deployment in "${deployments[@]}"; do
        if kubectl get deployment "$deployment" -n "$NAMESPACE" >/dev/null 2>&1; then
            local ready_replicas
            ready_replicas=$(kubectl get deployment "$deployment" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')
            local desired_replicas
            desired_replicas=$(kubectl get deployment "$deployment" -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
            
            if [[ "$ready_replicas" == "$desired_replicas" ]] && [[ "$ready_replicas" -gt 0 ]]; then
                log_success "Deployment $deployment is healthy ($ready_replicas/$desired_replicas ready)"
            else
                log_warning "Deployment $deployment is not fully ready ($ready_replicas/$desired_replicas ready)"
                all_healthy=false
            fi
        else
            log_error "Deployment $deployment not found"
            all_healthy=false
        fi
    done
    
    if $all_healthy; then
        health_results["deployments"]="PASS"
    else
        health_results["deployments"]="WARN"
    fi
}

# Check pods
check_pods() {
    log_info "Checking pod health..."
    
    local pods
    pods=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')
    
    if [[ -z "$pods" ]]; then
        health_results["pods"]="FAIL"
        log_error "No pods found in namespace $NAMESPACE"
        return 1
    fi
    
    local healthy_pods=0
    local total_pods=0
    
    for pod in $pods; do
        ((total_pods++))
        
        local status
        status=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.phase}')
        
        local ready
        ready=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
        
        if [[ "$status" == "Running" ]] && [[ "$ready" == "True" ]]; then
            ((healthy_pods++))
            if [[ "$VERBOSE" == "true" ]]; then
                log_success "Pod $pod is healthy"
            fi
        else
            log_warning "Pod $pod is not healthy (Status: $status, Ready: $ready)"
        fi
    done
    
    log_info "Pod health: $healthy_pods/$total_pods healthy"
    
    if [[ $healthy_pods -eq $total_pods ]] && [[ $total_pods -gt 0 ]]; then
        health_results["pods"]="PASS"
    elif [[ $healthy_pods -gt 0 ]]; then
        health_results["pods"]="WARN"
    else
        health_results["pods"]="FAIL"
    fi
}

# Check services
check_services() {
    log_info "Checking services..."
    
    local services=("compliance-sentinel-service")
    local all_healthy=true
    
    for service in "${services[@]}"; do
        if kubectl get service "$service" -n "$NAMESPACE" >/dev/null 2>&1; then
            local endpoints
            endpoints=$(kubectl get endpoints "$service" -n "$NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}' | wc -w)
            
            if [[ $endpoints -gt 0 ]]; then
                log_success "Service $service has $endpoints endpoints"
            else
                log_warning "Service $service has no endpoints"
                all_healthy=false
            fi
        else
            log_error "Service $service not found"
            all_healthy=false
        fi
    done
    
    if $all_healthy; then
        health_results["services"]="PASS"
    else
        health_results["services"]="WARN"
    fi
}

# Check application health endpoint
check_application_health() {
    log_info "Checking application health endpoint..."
    
    # Port forward to access the health endpoint
    local port=8080
    kubectl port-forward -n "$NAMESPACE" service/compliance-sentinel-service "$port:8000" >/dev/null 2>&1 &
    local port_forward_pid=$!
    
    # Wait for port forward to be ready
    sleep 2
    
    # Check health endpoint
    if curl -f -s "http://localhost:$port/health" >/dev/null 2>&1; then
        health_results["app_health"]="PASS"
        log_success "Application health endpoint is responding"
    else
        health_results["app_health"]="FAIL"
        log_error "Application health endpoint is not responding"
    fi
    
    # Clean up port forward
    kill $port_forward_pid 2>/dev/null || true
}

# Check resource usage
check_resource_usage() {
    log_info "Checking resource usage..."
    
    # Check CPU and memory usage
    local pods
    pods=$(kubectl get pods -n "$NAMESPACE" -l app=compliance-sentinel -o jsonpath='{.items[*].metadata.name}')
    
    local high_usage=false
    
    for pod in $pods; do
        if kubectl top pod "$pod" -n "$NAMESPACE" >/dev/null 2>&1; then
            local cpu_usage
            cpu_usage=$(kubectl top pod "$pod" -n "$NAMESPACE" --no-headers | awk '{print $2}' | sed 's/m//')
            
            local memory_usage
            memory_usage=$(kubectl top pod "$pod" -n "$NAMESPACE" --no-headers | awk '{print $3}' | sed 's/Mi//')
            
            # Check if CPU usage is above 80% (assuming 1000m = 100%)
            if [[ $cpu_usage -gt 800 ]]; then
                log_warning "Pod $pod has high CPU usage: ${cpu_usage}m"
                high_usage=true
            fi
            
            # Check if memory usage is above 1.5GB
            if [[ $memory_usage -gt 1536 ]]; then
                log_warning "Pod $pod has high memory usage: ${memory_usage}Mi"
                high_usage=true
            fi
            
            if [[ "$VERBOSE" == "true" ]]; then
                log_info "Pod $pod - CPU: ${cpu_usage}m, Memory: ${memory_usage}Mi"
            fi
        fi
    done
    
    if $high_usage; then
        health_results["resources"]="WARN"
    else
        health_results["resources"]="PASS"
        log_success "Resource usage is within normal limits"
    fi
}

# Check persistent volumes
check_persistent_volumes() {
    log_info "Checking persistent volumes..."
    
    local pvcs
    pvcs=$(kubectl get pvc -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')
    
    if [[ -z "$pvcs" ]]; then
        health_results["storage"]="WARN"
        log_warning "No persistent volume claims found"
        return
    fi
    
    local all_bound=true
    
    for pvc in $pvcs; do
        local status
        status=$(kubectl get pvc "$pvc" -n "$NAMESPACE" -o jsonpath='{.status.phase}')
        
        if [[ "$status" == "Bound" ]]; then
            if [[ "$VERBOSE" == "true" ]]; then
                log_success "PVC $pvc is bound"
            fi
        else
            log_warning "PVC $pvc is not bound (Status: $status)"
            all_bound=false
        fi
    done
    
    if $all_bound; then
        health_results["storage"]="PASS"
        log_success "All persistent volumes are bound"
    else
        health_results["storage"]="WARN"
    fi
}

# Check ingress
check_ingress() {
    log_info "Checking ingress..."
    
    if kubectl get ingress -n "$NAMESPACE" >/dev/null 2>&1; then
        local ingresses
        ingresses=$(kubectl get ingress -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')
        
        for ingress in $ingresses; do
            local hosts
            hosts=$(kubectl get ingress "$ingress" -n "$NAMESPACE" -o jsonpath='{.spec.rules[*].host}')
            
            log_success "Ingress $ingress configured for hosts: $hosts"
        done
        
        health_results["ingress"]="PASS"
    else
        health_results["ingress"]="WARN"
        log_warning "No ingress resources found"
    fi
}

# Generate health report
generate_report() {
    echo
    echo "=================================="
    echo "    HEALTH CHECK REPORT"
    echo "=================================="
    echo "Timestamp: $(date)"
    echo "Namespace: $NAMESPACE"
    echo
    
    local overall_status="PASS"
    
    for check in "${!health_results[@]}"; do
        local status="${health_results[$check]}"
        local color=""
        
        case $status in
            "PASS")
                color="$GREEN"
                ;;
            "WARN")
                color="$YELLOW"
                if [[ "$overall_status" == "PASS" ]]; then
                    overall_status="WARN"
                fi
                ;;
            "FAIL")
                color="$RED"
                overall_status="FAIL"
                ;;
        esac
        
        printf "%-20s: %b%s%b\n" "$check" "$color" "$status" "$NC"
    done
    
    echo
    echo "=================================="
    local overall_color=""
    case $overall_status in
        "PASS")
            overall_color="$GREEN"
            ;;
        "WARN")
            overall_color="$YELLOW"
            ;;
        "FAIL")
            overall_color="$RED"
            ;;
    esac
    
    printf "Overall Status: %b%s%b\n" "$overall_color" "$overall_status" "$NC"
    echo "=================================="
    
    # Exit with appropriate code
    case $overall_status in
        "PASS")
            exit 0
            ;;
        "WARN")
            exit 1
            ;;
        "FAIL")
            exit 2
            ;;
    esac
}

# Main execution
main() {
    echo "Starting health check for Compliance Sentinel..."
    echo
    
    # Run all health checks
    check_kubernetes || true
    check_namespace || true
    check_deployments || true
    check_pods || true
    check_services || true
    check_application_health || true
    check_resource_usage || true
    check_persistent_volumes || true
    check_ingress || true
    
    # Generate final report
    generate_report
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE="true"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -n, --namespace   Kubernetes namespace (default: compliance-sentinel)"
            echo "  -t, --timeout     Timeout in seconds (default: 30)"
            echo "  -v, --verbose     Verbose output"
            echo "  -h, --help        Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main