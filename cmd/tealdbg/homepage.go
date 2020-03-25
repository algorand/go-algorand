package main

const homepage = `
<h1>Hello, world!</h1>

<script>
const socket = new WebSocket('ws://localhost:9392/ws');

socket.addEventListener('open', function (event) {
    socket.send('opened');
});

socket.addEventListener('message', function (event) {
    var msg = JSON.parse(event.data);
    console.log('received: ', JSON.stringify(msg));

    if (msg["event"] === "registered" || msg["event"] === "updated") {
        console.log('continuing');
        var req = new XMLHttpRequest();
        req.open("POST", "/exec/continue");
        req.setRequestHeader("Content-Type", "application/json");
        req.send(JSON.stringify({"execid": msg["state"]["execid"]}));
    }

});
</script>
`
