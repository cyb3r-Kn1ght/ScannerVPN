# Makefile for Controller only
# For VM1 (Ubuntu - 10.102.199.42)

.PHONY: help build push deploy logs clean test health rebuild port-forward-external port-forward-external-bg test-external status clean-jobs logs-detailed debug test-vpn-assignment test-connectivity logs-recent-job

REGISTRY := nguyenminhnguyen
TAG      := latest
NAMESPACE := scan-system

help:
	@echo "Controller Build & Deploy"
	@echo "========================"
	@echo "Available commands:"
	@echo "  make build               Build controller image"
	@echo "  make push                Push controller to Docker Hub"
	@echo "  make deploy              Deploy controller to K8s"
	@echo "  make logs                View controller logs"
	@echo "  make logs-detailed       View detailed controller logs"
	@echo "  make clean               Clean controller resources"
	@echo "  make clean-jobs          Clean old scan jobs"
	@echo "  make test                Test controller APIs"
	@echo "  make test-connectivity   Test cross-VM connectivity"
	@echo "  make test-vpn-assignment Test VPN assignment feature"
	@echo "  make health              Health check controller"
	@echo "  make status              Show comprehensive system status"
	@echo "  make debug               Show detailed debug information"
	@echo "  make rebuild             Clean, build and redeploy"
	@echo "  make port-forward-external   External port forwarding"
	@echo "  make logs-recent-job     View most recent scan job logs"

build:
	@echo "🔨 Building Controller image..."
	@eval $$(minikube docker-env); docker build --no-cache -f Dockerfile -t $(REGISTRY)/controller:$(TAG) .
	@echo "✅ Controller image built: $(REGISTRY)/controller:$(TAG)"

push: build
	@echo "🚀 Pushing Controller to Docker Hub..."
	docker push $(REGISTRY)/controller:$(TAG)
	@echo "✅ Controller image pushed"

deploy:
	@echo "🚀 Deploying Controller to Kubernetes..."
	kubectl apply -f ../manifests/namespace.yaml
	kubectl apply -f ../manifests/controller-rbac.yaml
	kubectl apply -f ../manifests/controller-deployment.yaml
	kubectl apply -f ../manifests/controller-service.yaml
	kubectl apply -f ../manifests/controller-nodeport.yaml
	@echo "⏳ Waiting for Controller to be ready..."
	kubectl wait --for=condition=available --timeout=300s deployment/controller -n $(NAMESPACE)
	@echo "✅ Controller deployed successfully"

logs:
	@echo "📋 Controller logs:"
	kubectl logs -n $(NAMESPACE) deployment/controller -f

clean:
	@echo "🧹 Cleaning Controller resources..."
	kubectl delete deployment controller -n $(NAMESPACE) --ignore-not-found
	kubectl delete service controller -n $(NAMESPACE) --ignore-not-found
	kubectl delete service controller-nodeport -n $(NAMESPACE) --ignore-not-found
	kubectl delete rolebinding controller-rolebinding -n $(NAMESPACE) --ignore-not-found
	kubectl delete role controller-role -n $(NAMESPACE) --ignore-not-found
	kubectl delete serviceaccount controller-sa -n $(NAMESPACE) --ignore-not-found

test:
	@echo "🧪 Testing Controller APIs..."
	@echo "Health check:"
	curl -f http://10.102.199.42:8000/health || echo "Health check failed"
	@echo "\nVPN API test:"
	curl -f http://10.102.199.42:8000/api/vpns || echo "VPN API failed"
	@echo "\nAPI docs:"
	curl -f http://10.102.199.42:8000/docs >/dev/null && echo "API docs OK" || echo "API docs failed"
	@echo "\nController Pod status:"
	kubectl get pods -n $(NAMESPACE) -l app=controller

health:
	@echo "🔍 Controller health check..."
	kubectl get pods -n $(NAMESPACE) -l app=controller
	@echo "Service status:"
	kubectl get svc -n $(NAMESPACE) controller controller-nodeport
	@echo "External access test:"
	curl -f http://10.102.199.42:8000/health && echo "✅ Controller healthy" || echo "❌ Controller not accessible"

rebuild: clean build deploy
	@echo "✅ Controller rebuilt and redeployed"

port-forward-external:
	@echo "🌐 Setting up external port forwarding for Controller..."
	@echo "Controller API will be available at http://10.102.199.42:8000"
	kubectl port-forward --address 0.0.0.0 -n $(NAMESPACE) service/controller 8000:8000

port-forward-external-bg:
	@echo "🌐 Setting up external background port forwarding for Controller..."
	@echo "Controller API will be available at http://10.102.199.42:8000"
	kubectl port-forward --address 0.0.0.0 -n $(NAMESPACE) service/controller 8000:8000 &

test-external:
	@echo "🧪 Testing Controller APIs via external port-forward..."
	@echo "Health check:"
	curl -f http://10.102.199.42:8000/health || echo "Health check failed"
	@echo "\nDebug info:"
	curl -f http://10.102.199.42:8000/debug/info || echo "Debug info failed"
	@echo "\nVPN API test (sync):"
	curl -f http://10.102.199.42:8000/api/vpns/test || echo "VPN API failed"
	@echo "\nTest scan job submission:"
	curl -X POST http://10.102.199.42:8000/api/scan/dns-lookup \
		-H "Content-Type: application/json" \
		-d '{"targets":["google.com"],"vpn_profile":"103.57.130.113.ovpn"}' \
		|| echo "Scan job submission failed"

logs-detailed:
	@echo "📋 Detailed Controller logs (last 100 lines):"
	kubectl logs -n $(NAMESPACE) deployment/controller --tail=100

status:
	@echo "📊 Controller System Status:"
	@echo "Pods:"
	kubectl get pods -n $(NAMESPACE) -l app=controller
	@echo "\nServices:"
	kubectl get svc -n $(NAMESPACE) controller controller-nodeport
	@echo "\nEndpoints:"
	kubectl get endpoints -n $(NAMESPACE) controller
	@echo "\nController Resources:"
	kubectl top pods -n $(NAMESPACE) --no-headers | grep controller || echo "Metrics not available"
	@echo "\nRecent Controller Events:"
	kubectl get events -n $(NAMESPACE) --sort-by=.metadata.creationTimestamp | grep controller | tail -5

clean-jobs:
	@echo "🧹 Cleaning old scan jobs from all namespaces..."
	kubectl delete jobs --field-selector status.successful=1 -n $(NAMESPACE) --ignore-not-found
	kubectl delete jobs --field-selector status.failed=1 -n $(NAMESPACE) --ignore-not-found
	@echo "✅ Old scan jobs cleaned"

debug:
	@echo "🔍 Controller Debug Information:"
	@echo "=== Pod Details ==="
	kubectl describe pods -n $(NAMESPACE) -l app=controller
	@echo "\n=== Service Details ==="
	kubectl describe svc -n $(NAMESPACE) controller
	@echo "\n=== Recent Events ==="
	kubectl get events -n $(NAMESPACE) --sort-by=.metadata.creationTimestamp | tail -10
	@echo "\n=== Controller Logs (last 50 lines) ==="
	kubectl logs -n $(NAMESPACE) deployment/controller --tail=50

test-vpn-assignment:
	@echo "🧪 Testing VPN Assignment Feature..."
	@echo "First, testing Scanner Node connectivity:"
	curl -f http://10.102.199.37:8000/health || echo "Scanner Node not accessible - check port-forward"
	@echo "\nTesting DNS lookup with specific VPN and country:"
	curl -X POST http://10.102.199.42:8000/api/scan/dns-lookup \
		-H "Content-Type: application/json" \
		-d '{"targets":["google.com","github.com"],"vpn_profile":"103.57.130.113.ovpn","country":"JP"}' \
		|| echo "VPN assignment test failed"
	@echo "\nTesting with VN VPN:"
	curl -X POST http://10.102.199.42:8000/api/scan/dns-lookup \
		-H "Content-Type: application/json" \
		-d '{"targets":["cloudflare.com"],"country":"VN"}' \
		|| echo "VN VPN test failed"
	@echo "\nTesting without VPN (should use random):"
	curl -X POST http://10.102.199.42:8000/api/scan/dns-lookup \
		-H "Content-Type: application/json" \
		-d '{"targets":["example.com"]}' \
		|| echo "Random VPN test failed"

test-connectivity:
	@echo "🔗 Testing cross-VM connectivity..."
	@echo "Controller health:"
	curl -f http://10.102.199.42:8000/health || echo "Controller not accessible"
	@echo "\nScanner Node health:"
	curl -f http://10.102.199.37:8000/health || echo "Scanner Node not accessible - run port-forward first"
	@echo "\nVPN Proxy health:"
	curl -f http://10.102.199.36:8000/health || echo "VPN Proxy not accessible"

logs-recent-job:
	@echo "📋 Recent scan job logs:"
	@latest_job=$$(kubectl get jobs -n $(NAMESPACE) --sort-by=.metadata.creationTimestamp -o name | tail -1); \
	if [ -n "$$latest_job" ]; then \
		echo "=== $$latest_job ==="; \
		kubectl logs -n $(NAMESPACE) $$latest_job --tail=50; \
	else \
		echo "No jobs found"; \
	fi
	
