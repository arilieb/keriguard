#!/bin/bash


# Issue Interface credential to keriguard for main file
kg interface create --name admin --alias admin \
                    --registry-name admin --recipient keriguard \
                    --interface-name wg0 --listen-port 43567 --address "10.0.0.4/24" \
                    --interface-description "Main Interface Credential" \
                    --output keriguard-w0.cesr \
                    --registrar-url http://localhost:8080/

kli vc list --name admin --alias admin --issued

# Issue Interface credential to peer
kg interface create --name admin --alias admin \
                    --registry-name admin --recipient peer \
                    --interface-name wg0 --listen-port 43567 --address "10.0.0.3/24" \
                    --interface-description "Main Interface Credential" \
                    --output peer-w0.cesr \
                    --registrar-url http://localhost:8080/

kli vc list --name admin --alias admin --issued
kli status --name admin --alias admin

kli oobi resolve --name keriguard --oobi-alias admin --oobi http://127.0.0.1:5642/oobi/EI6-tTwfonE2nKknuUkhkwRe-Op7kTYIeCUJcuuMUFUr/witness --force
kli oobi resolve --name peer --oobi-alias admin --oobi http://127.0.0.1:5642/oobi/EI6-tTwfonE2nKknuUkhkwRe-Op7kTYIeCUJcuuMUFUr/witness --force

kg guardian connect --name keriguard --alias keriguard --file keriguard-w0.cesr --export-dir ./wireguard/keriguard
kg guardian connect --name peer --alias peer --file peer-w0.cesr --export-dir ./wireguard/peer

kg peers connect --name admin --alias admin --peer "name=keriguard,endpoint=147.182.240.249:43567,allowed-ips=10.0.0.4/32,environment=production" \
                                            --peer "name=peer,endpoint=143.56.178.5:43567,allowed-ips=10.0.0.3/32,environment=production" \
                                            --output keriguard-peer-connection.cesr \
                                            --registrar-url http://localhost:8080/

kli vc list --name admin --alias admin --issued

kli status --name admin --alias admin
