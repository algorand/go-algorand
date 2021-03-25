chmod 700 kmd-v0.5
chmod 700 kmd-v0.5/sqlite_wallets
rm -rf net-v1 relay/net-v1;
find . -name "*.log" -delete;
find . -name "algod*" -delete;
mkdir net-v1;
cp ./Wallet1.0.3000000.partkey ./net-v1;
goal node start -d ./relay;
goal node start -d . -p 127.0.0.1:7000;
goal node wait -d ./relay -w 20
sleep 2s
pingpong run -d . --rest 0 --run 5 --refresh 1 --numaccounts 500 --tps 1000 > /dev/null &
pingpongPID=$!
echo "sleeping for a while to let the load to build up..."
sleep 600s
echo "done"
kill -9 $pingpongPID
curl http://$(cat ./relay/algod.net)/urlAuth/$(cat ./relay/algod.admin.token)/debug/pprof/heap > heap.profile
goal node status -d .
top -pid $(cat ./relay/algod.pid) -l 1
goal node stop -d .;
goal node stop -d ./relay;
go tool pprof -png heap.profile

