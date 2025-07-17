# How to start the example

´´´
export
JWKS_ENDPOINT_URL=https://login.microsoftonline.com/b52245db-4800-4792-975a-1d9ed49512f2/discovery/v2.0/keys?appid=bd621c7c-d51d-4f86-a3fa-5d842c63dfce
export OIDC_AUD=api://bd621c7c-d51d-4f86-a3fa-5d842c63dfce
export CLUSTERID=Pas3OEVBNTcwNTJENDM2Qz
docker compose up -d
´´´

# Broker configuration

TODO: Explain docker-compose file and need of confluent-oauth-extensions

# Useful commands

kafka-topics --command-config /tmp/client.properties --bootstrap-server big-host-1.datadisorder.dev:9093 --list
kafka-topics --command-config /tmp/client.properties --bootstrap-server big-host-1.datadisorder.dev:9093 --create
--topic test-private
