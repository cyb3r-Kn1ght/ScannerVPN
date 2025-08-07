#!/bin/bash
#
# Scanner Node API Build Script for VM2 (Kali - 10.102.199.37)
#
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

REGISTRY="nguyenminhnguyen"
TAG="latest"

usage() {
  cat <<EOF
Usage: $0 {build|build-tools|build-all|push|deploy|full|clean|test}

  build       Build scanner-node-api image only
  build-tools Build all scan tool images
  build-all   Build scanner-node-api + tools
  push        Build all and push to Docker Hub
  deploy      Deploy scanner node to K8s
  full        Build + Push + Deploy
  clean       Clean scanner resources
  test        Test scanner node APIs

EOF
}

case "$1" in
  build)
    echo -e "${BLUE}🔨 Building Scanner Node API image...${NC}"
    docker build -t $REGISTRY/scanner-node-api:$TAG .
    echo -e "${GREEN}✅ Scanner Node API image built: $REGISTRY/scanner-node-api:$TAG${NC}"
    ;;

  build-tools)
    echo -e "${BLUE}🔨 Building scan tool images...${NC}"
    docker build -t $REGISTRY/dns-lookup:$TAG ../scan-node-tools/dns-lookup
    docker build -t $REGISTRY/port-scan:$TAG ../scan-node-tools/port-scan
    docker build -t $REGISTRY/httpx-scan:$TAG ../scan-node-tools/httpx-scan
    echo -e "${GREEN}✅ All scan tool images built${NC}"
    ;;

  build-all)
    echo -e "${BLUE}🔨 Building Scanner Node API + Tools...${NC}"
    $0 build
    $0 build-tools
    echo -e "${GREEN}✅ All Scanner Node components built${NC}"
    ;;

  push)
    echo -e "${BLUE}🔨 Building and pushing Scanner Node components...${NC}"
    $0 build-all
    docker push $REGISTRY/scanner-node-api:$TAG
    docker push $REGISTRY/dns-lookup:$TAG
    docker push $REGISTRY/port-scan:$TAG
    docker push $REGISTRY/httpx-scan:$TAG
    echo -e "${GREEN}✅ All Scanner Node images pushed to Docker Hub${NC}"
    ;;

  deploy)
    echo -e "${BLUE}🚀 Deploying Scanner Node to Kubernetes...${NC}"
    kubectl apply -f ../manifests/namespace.yaml
    kubectl apply -f ../manifests/scanner-node-rbac.yaml
    kubectl apply -f ../manifests/scanner-node-api-deployment.yaml
    kubectl apply -f ../manifests/scanner-node-api-service.yaml
    
    echo -e "${YELLOW}⏳ Waiting for Scanner Node to be ready...${NC}"
    kubectl wait --for=condition=available --timeout=300s deployment/scanner-node-api -n scan-system
    
    echo -e "${GREEN}✅ Scanner Node deployed successfully${NC}"
    echo -e "${BLUE}📋 Scanner Node status:${NC}"
    kubectl get pods,svc -n scan-system -l app=scanner-node-api
    ;;

  full)
    echo -e "${BLUE}🚀 Full deployment: Build + Push + Deploy${NC}"
    $0 push
    $0 deploy
    echo -e "${GREEN}✅ Full Scanner Node deployment completed${NC}"
    ;;

  clean)
    echo -e "${YELLOW}🧹 Cleaning Scanner Node resources...${NC}"
    kubectl delete deployment scanner-node-api -n scan-system --ignore-not-found
    kubectl delete service scanner-node-api -n scan-system --ignore-not-found
    kubectl delete jobs --all -n scan-system --ignore-not-found
    echo -e "${GREEN}✅ Scanner Node resources cleaned${NC}"
    ;;

  test)
    echo -e "${BLUE}🧪 Testing Scanner Node...${NC}"
    echo "Pod status:"
    kubectl get pods -n scan-system -l app=scanner-node-api
    
    echo "Service status:"
    kubectl get svc -n scan-system scanner-node-api
    
    echo "Health check:"
    kubectl exec -n scan-system deployment/scanner-node-api -- curl -f http://localhost:8000/health && echo -e "${GREEN}✅ Health OK${NC}" || echo -e "${RED}❌ Health failed${NC}"
    ;;

  *)
    usage
    ;;
esac
