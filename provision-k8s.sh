#! /bin/sh
# ==================================================================
#  _                                         
# | |                                        
# | |     __ _ _ __ ___   __ _ ___ ___ _   _ 
# | |    / _` | '_ ` _ \ / _` / __/ __| | | |
# | |___| (_| | | | | | | (_| \__ \__ \ |_| |
# |______\__,_|_| |_| |_|\__,_|___/___/\__,_|
#                                            
#                                            
# ==================================================================

minikube kubectl -- create secret generic scep-db-secrets --from-literal=dbuser=$POSTGRES_USER --from-literal=dbpassword=$POSTGRES_PASSWORD
minikube kubectl -- create configmap scep-db-config --from-file=./db/create.sql

minikube kubectl -- create secret generic proxy-server-certs --from-file=./proxy/server/certs/scepproxy.crt --from-file=./proxy/server/certs/scepproxy.key 
minikube kubectl -- create secret generic proxy-client-certs --from-file=./proxy/client/certs/enroller.crt

minikube kubectl -- create secret generic scep-ca --from-file=./ca/ca.pem --from-file=./ca/ca.key
minikube kubectl -- create secret generic scep-certs --from-file=./certs/consul.crt --from-file=./certs/vault.crt

minikube kubectl -- create secret generic scepextension-certs --from-file=./certs/consul.crt --from-file=./certs/extension.crt --from-file=./certs/extension.key --from-file=./certs/scepproxy.crt

minikube kubectl -- create secret generic scepca1-vault-secrets --from-literal=roleid=$CA1_ROLEID --from-literal=secretid=$CA1_SECRETID
minikube kubectl -- create secret generic scepca2-vault-secrets --from-literal=roleid=$CA2_ROLEID --from-literal=secretid=$CA2_SECRETID
minikube kubectl -- create secret generic scepca3-vault-secrets --from-literal=roleid=$CA3_ROLEID --from-literal=secretid=$CA3_SECRETID
minikube kubectl -- create secret generic scepca4-vault-secrets --from-literal=roleid=$CA4_ROLEID --from-literal=secretid=$CA4_SECRETID

minikube kubectl -- apply -f k8s/scepproxy-deployment.yml
minikube kubectl -- apply -f k8s/scepproxy-service.yml

minikube kubectl -- apply -f k8s/scepextension-deployment.yml
minikube kubectl -- apply -f k8s/scepextension-service.yml

minikube kubectl -- apply -f k8s/scepdb-pv.yml
minikube kubectl -- apply -f k8s/scepdb-deployment.yml
minikube kubectl -- apply -f k8s/scepdb-service.yml

minikube kubectl -- apply -f k8s/scep-pv.yml

minikube kubectl -- apply -f k8s/scepca1-deployment.yml
minikube kubectl -- apply -f k8s/scepca1-service.yml

minikube kubectl -- apply -f k8s/scepca2-deployment.yml
minikube kubectl -- apply -f k8s/scepca2-service.yml

minikube kubectl -- apply -f k8s/scepca3-deployment.yml
minikube kubectl -- apply -f k8s/scepca3-service.yml

minikube kubectl -- apply -f k8s/scepca4-deployment.yml
minikube kubectl -- apply -f k8s/scepca4-service.yml