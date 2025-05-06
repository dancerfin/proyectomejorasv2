#!/bin/bash
# Tráfico normal entre todos los hosts
SERVERS=("10.1.1.5" "10.1.1.7" "10.1.1.9" "10.1.1.11" "10.1.1.13")  # Hosts servidores

for i in {1..10000}
do
   echo "Generando tráfico normal, iteración $i"
   
   # Ping aleatorio a servidores
   target=${SERVERS[$((RANDOM % ${#SERVERS[@]}))]}
   ping -c1 $target
   
   # Tráfico HTTP simulado
   if (( i % 5 == 0 )); then
      curl -m 2 http://$target &> /dev/null
   fi
   
   # Tráfico UDP aleatorio
   if (( i % 7 == 0 )); then
      hping3 -2 -c 5 -d 64 -p 53 $target &> /dev/null &
   fi
   
   # Intervalo aleatorio entre 1-20 segundos
   sleep $((1 + RANDOM % 20))
done