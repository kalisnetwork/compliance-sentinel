#!/bin/bash

# Compliance Sentinel Deployment Script
# This script handles deployment to different environments

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT="${ENVIRONMENT:-development}"
NAMESPACE="compliance-sentinel"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REGISTRY="${REGISTRY:-compliance-sentinel}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Help function
show_help() {
    cat << EOF
Compliance Sentinel Deployment Script

Usage: $0 [OPTIONS] COMMAND

Commands:
    build           Build Docker images
    push            Push images to registry
    deploy          Deploy to Kubernetes
    rollback        Rollback to previous version
    status          Check deployment status
    logs            Show application logs
    cleanup         Clean up resources

Options:
    -e, --environment   Environment (development|staging|production) [default: development]
    -t, --tag          Image tag [default: latest]
    -r, --registry     Container registry [default: compliance-sentinel]
    -n, --namespace    Kubernetes namespace [default: compliance-sentinel]
    -h, --help         Show this help message

Examples:
    $0 build
    $0 -e production -t v1.2.3 deploy
    $0 -e staging rollback
    $0 status
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -t|--tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            -r|--registry)
                REGISTRY="$2"
                shift 2
                ;;
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            build|push|deploy|rollback|status|logs|cleanup)
                COMMAND="$1"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    if [[ -z "${COMMAND:-}" ]]; then
        log_error "No command specified"
        show_help
        exit 1
    fi
}

# Validate environment
validate_environment() {
    case $ENVIRONMENT in
        development|staging|production)
            log_info "Deploying to environment: $ENVIRONMENT"
            ;;
        *)
            log_error "Invalid environment: $ENVIRONMENT"
            exit 1
            ;;
    esac
}

# Check prerequisites
check_prerequisites() {
    local missing_tools=()

    # Check required tools
    command -v docker >/dev/null 2>&1 || missing_tools+=("docker")
    command -v kubectl >/dev/null 2>&1 || missing_tools+=("kubectl")
    command -v helm >/dev/null 2>&1 || missing_tools+=("helm")

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi

    # Check Kubernetes connection
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Build Docker images
build_images() {
    log_info "Building Docker images..."

    cd "$PROJECT_ROOT"

    # Build main application image
    docker build \
        --target production \
        --tag "${REGISTRY}:${IMAGE_TAG}" \
        --tag "${REGISTRY}:latest" \
        .

    # Build scanner image
    docker build \
        --target scanner \
        --tag "${REGISTRY}-scanner:${IMAGE_TAG}" \
        --tag "${REGISTRY}-scanner:latest" \
        .

    log_success "Docker images built successfully"
}

# Push images to registry
push_images() {
    log_info "Pushing images to registry..."

    # Push main image
    docker push "${REGISTRY}:${IMAGE_TAG}"
    docker push "${REGISTRY}:latest"

    # Push scanner image
    docker push "${REGISTRY}-scanner:${IMAGE_TAG}"
    docker push "${REGISTRY}-scanner:latest"

    log_success "Images pushed successfully"
}

# Deploy to Kubernetes
deploy_to_kubernetes() {
    log_info "Deploying to Kubernetes..."

    cd "$PROJECT_ROOT"

    # Create namespace if it doesn't exist
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    # Apply Kubernetes manifests
    log_info "Applying Kubernetes manifests..."

    # Apply in order
    kubectl apply -f k8s/namespace.yaml
    kubectl apply -f k8s/rbac.yaml
    kubectl apply -f k8s/configmap.yaml
    kubectl apply -f k8s/secret.yaml
    kubectl apply -f k8s/pvc.yaml
    kubectl apply -f k8s/deployment.yaml
    kubectl apply -f k8s/service.yaml
    kubectl apply -f k8s/hpa.yaml

    # Wait for deployment to be ready
    log_info "Waiting for deployment to be ready..."
    kubectl rollout status deployment/compliance-sentinel -n "$NAMESPACE" --timeout=600s
    kubectl rollout status deployment/compliance-sentinel-worker -n "$NAMESPACE" --timeout=600s

    # Run database migrations if needed
    if [[ "$ENVIRONMENT" != "development" ]]; then
        log_info "Running database migrations..."
        kubectl run migration-job \
            --image="${REGISTRY}:${IMAGE_TAG}" \
            --restart=Never \
            --rm -i \
            --namespace="$NAMESPACE" \
            -- python -m compliance_sentinel.database.migrate
    fi

    log_success "Deployment completed successfully"
}

# Rollback deployment
rollback_deployment() {
    log_info "Rolling back deployment..."

    kubectl rollout undo deployment/compliance-sentinel -n "$NAMESPACE"
    kubectl rollout undo deployment/compliance-sentinel-worker -n "$NAMESPACE"

    # Wait for rollback to complete
    kubectl rollout status deployment/compliance-sentinel -n "$NAMESPACE" --timeout=300s
    kubectl rollout status deployment/compliance-sentinel-worker -n "$NAMESPACE" --timeout=300s

    log_success "Rollback completed successfully"
}

# Check deployment status
check_status() {
    log_info "Checking deployment status..."

    echo
    echo "=== Namespace ==="
    kubectl get namespace "$NAMESPACE" 2>/dev/null || log_warning "Namespace not found"

    echo
    echo "=== Deployments ==="
    kubectl get deployments -n "$NAMESPACE" 2>/dev/null || log_warning "No deployments found"

    echo
    echo "=== Pods ==="
    kubectl get pods -n "$NAMESPACE" 2>/dev/null || log_warning "No pods found"

    echo
    echo "=== Services ==="
    kubectl get services -n "$NAMESPACE" 2>/dev/null || log_warning "No services found"

    echo
    echo "=== Ingress ==="
    kubectl get ingress -n "$NAMESPACE" 2>/dev/null || log_warning "No ingress found"

    echo
    echo "=== HPA ==="
    kubectl get hpa -n "$NAMESPACE" 2>/dev/null || log_warning "No HPA found"

    echo
    echo "=== Recent Events ==="
    kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' | tail -10
}

# Show application logs
show_logs() {
    log_info "Showing application logs..."

    # Get pod names
    local pods
    pods=$(kubectl get pods -n "$NAMESPACE" -l app=compliance-sentinel -o jsonpath='{.items[*].metadata.name}')

    if [[ -z "$pods" ]]; then
        log_warning "No pods found"
        return
    fi

    # Show logs from all pods
    for pod in $pods; do
        echo
        echo "=== Logs from $pod ==="
        kubectl logs "$pod" -n "$NAMESPACE" --tail=50
    done
}

# Cleanup resources
cleanup_resources() {
    log_warning "This will delete all resources in namespace: $NAMESPACE"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Cleaning up resources..."

        # Delete all resources in namespace
        kubectl delete all --all -n "$NAMESPACE"
        kubectl delete pvc --all -n "$NAMESPACE"
        kubectl delete configmap --all -n "$NAMESPACE"
        kubectl delete secret --all -n "$NAMESPACE"

        # Delete namespace
        kubectl delete namespace "$NAMESPACE"

        log_success "Cleanup completed"
    else
        log_info "Cleanup cancelled"
    fi
}

# Main execution
main() {
    parse_args "$@"
    validate_environment
    check_prerequisites

    case $COMMAND in
        build)
            build_images
            ;;
        push)
            push_images
            ;;
        deploy)
            build_images
            push_images
            deploy_to_kubernetes
            ;;
        rollback)
            rollback_deployment
            ;;
        status)
            check_status
            ;;
        logs)
            show_logs
            ;;
        cleanup)
            cleanup_resources
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"