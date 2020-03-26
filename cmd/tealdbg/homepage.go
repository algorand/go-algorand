package main

var homepage = `
<html>
    <head>
        <style>
            body {
                font-family: "Courier New", Courier, monospace;
                white-space: nowrap;
            }

            .execwrapper {
                width: 750px;
                height: 500px;
                margin: 25px auto 25px auto;
                border: 10px solid blue;
            }

            .execwrapper table {
                table-layout: fixed;
                width: 100%;
                height: 100%;
            }

            table.execution, .execution td {
                text-align: center;
                border: 1px solid black;
            }

            .disasm {
                width: 50%;
            }

            table.codetable {
                height: auto;
                white-space: nowrap;
            }

            .codetable td {
                border: none;
                text-align: left;
                font-size: 10px;
            }

            table.memtable {
                height: auto;
            }

            .memtable {
                table-layout: fixed;
            }

            .memtable td {
                font-size: 10px;
            }

            .memtable tr {
                height: 15px;
            }

            div.memwrapper {
                height: 165px;
                overflow-y: scroll;
            }

            .memwrapper p {
                font-size: 10px;
                padding: 0;
                margin: 2px;
                font-weight: bold;
            }

            .green {
                background-color: #93F593;
            }

            .codetable tr {
                height: 10px;
            }

            div.codewrapper {
                height: 350px;
                overflow-y: scroll;
            }

            table.codetable {
                table-layout: fixed;
            }

            .codetable td:nth-child(1) {
                width: 7%;
            }

            .codetable td:nth-child(2) {
                width: 10%;
            }

            .codetable td:nth-child(3) {
                width: 83%;
            }

            .memtable td:nth-child(1) {
                width: 10%;
            }

            .memtable td:nth-child(2) {
                width: 10%;
            }

            .memtable td:nth-child(3) {
                width: 80%;
            }
        </style>
    </head>

    <body>
        <h2 id="loading">waiting for connection from TEAL...</h2>
        <template id="exectemplate">
            <div class="execwrapper">
                <table class="execution">
                    <tbody>
                        <tr><td class="exectitle" colspan="2">Execution XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</td></tr>
                        <tr>
                            <td class="disasm">
                                <div class="codewrapper">
                                    <table class="codetable">
                                        <tbody>
                                        </tbody>
                                    </table>
                                </div>
                            </td>
                            <td class="memory">
                                <table>
                                    <tbody>
                                        <tr>
                                            <td>
                                                <div class="memwrapper">
                                                    <p>stack</p>
                                                    <table class="stack memtable">
                                                        <tbody>
                                                        </tbody>
                                                    </table>
                                                </div>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td>
                                                <div class="memwrapper">
                                                    <p>scratch</p>
                                                    <table class="scratch memtable">
                                                        <tbody>
                                                        </tbody>
                                                    </table>
                                                </div>
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </td>
                        </tr>
                        <tr class="globals">
                            <td class="pc">PC: foo</td>
                            <td class="error">Error: null</td>
                        </tr>
                        <tr class="actions">
                            <td><button class="setbp">Set breakpoints / continue</button></td><td><button class="single">Single step</button></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </template>

        <div id="sessions">
        </div>

        <script>
            var sessions = {};
            function addExec(state) {
                var template = document.getElementById("exectemplate");
                template = template.content.firstElementChild;
                var clone = template.cloneNode(true)
                setExecContents(clone, state);

                var sesslist = document.getElementById("sessions");
                sesslist.appendChild(clone);

                // Add to global session store so we can update
                sessions[state["execid"]] = clone;
            }

            function updateMemory(table, values) {
                table.innerHTML = "";
                for (var i = 0; i < values.length; i++) {
                    var row = table.insertRow(-1);
                    var lineno = row.insertCell(0);
                    var type = row.insertCell(1);
                    var value = row.insertCell(2);
                    lineno.innerText = i;
                    lineno.innerText = lineno.innerText.padStart(4, '0');

                    type.innerText = values[i]["t"];
                    if (values[i]["t"] === "u") {
                        value.innerText = values[i]["u"] || 0;
                    } else {
                        value.innerText = values[i]["b"] || "";
                    }
                }
            }

            function setExecContents(exec, state) {
                exec.querySelector(".exectitle").innerText = "Execution " + state["execid"];

                // Update stack and scratch
                var stacktable = exec.querySelector(".stack");
                updateMemory(stacktable, state["stack"])

                var scratchtable = exec.querySelector(".scratch");
                updateMemory(scratchtable, state["scratch"])

                var codelines = state["disasm"].split("\n");
                var codetable = exec.querySelector(".codetable");

                // Only update code if needed
                if (codetable.rows.length == 0) {
                    // Last line is always a blank newline, so skip it
                    for (var i = 0; i < codelines.length; i++) {
                        var row = codetable.insertRow(-1);
                        var brk = row.insertCell(0);
                        var lineno = row.insertCell(1);
                        var codeline = row.insertCell(2);

                        var checkbox = document.createElement("input");
                        checkbox.setAttribute("type", "checkbox");
                        brk.appendChild(checkbox);

                        lineno.innerText = i;
                        lineno.innerText = lineno.innerText.padStart(4, '0');
                        codeline.innerText = codelines[i];
                    }
                }

                var pc = exec.querySelector(".pc");
                pc.innerText = "PC: " + state["pc"];

                var error = exec.querySelector(".error");
                error.innerText = "Error: " + state["error"];

                var curHighlight = codetable.querySelector(".green");
                if (curHighlight) {
                    curHighlight.classList.toggle("green", false);
                }

                var highlightLine = pcToLine(state["pc"], state["disasm"], state["pctooffset"]);
                var rows = codetable.querySelectorAll("tr");
                rows[highlightLine].classList.toggle("green", true);

                var codewrapper = exec.querySelector(".codewrapper");

                // Scroll hit line into view
                if ((codewrapper.scrollTop + codewrapper.offsetHeight) < rows[highlightLine].offsetTop) {
                    codewrapper.scrollTop = rows[highlightLine].offsetTop;
                }

                var buttonHandler = function(singlestep) {
                    return function() {
                        var nextpc = 0;
                        if (!singlestep) {
                            // Iterate over breakpoints and find the next one greater
                            // than the current PC. If none, don't break at all (-1).
                            nextpc = -1;
                            var checkboxes = exec.querySelectorAll("input");
                            for (var i = 0; i < checkboxes.length; i++) {
                                if (checkboxes[i].checked) {
                                    nextpc = lineToPC(state["disasm"], i, state["pctooffset"]);
                                    // If breakpoint is greater than current pc, break on it
                                    if (nextpc > state["pc"]) {
                                        break;
                                    }
                                }
                            }
                        }

                        // Tell server to notify us on this PC
                        var req = new XMLHttpRequest();
                        req.open("POST", "/exec/config", false);
                        req.setRequestHeader("Content-Type", "application/json");
                        req.send(JSON.stringify({"execid": state["execid"], "breakonpc": nextpc}));

                        // Tell server to continue
                        req = new XMLHttpRequest();
                        req.open("POST", "/exec/continue");
                        req.setRequestHeader("Content-Type", "application/json");
                        req.send(JSON.stringify({"execid": state["execid"]}));
                    }
                }

                // Add onclick handlers
                var bpbutton = exec.querySelector(".setbp");
                var ssbutton = exec.querySelector(".single");

                bpbutton.onclick = buttonHandler(false);
                ssbutton.onclick = buttonHandler(true);
            }

            function lineToPC(disasm, line, pcToOffset) {
                if (pcToOffset.length == 0) {
                    return -1;
                }

                var offset = disasm.split("\n").slice(0, line).join("\n").length;
                for (var i = 0; i < pcToOffset.length; i++) {
                    if (pcToOffset[i]["offset"] >= offset) {
                        return pcToOffset[i]["pc"]
                    }
                }
            }

            function pcToLine(pc, disasm, pcToOffset) {
                if (pcToOffset.length == 0) {
                    return 0;
                }

                var offset = 0;
                for (var i = 0; i < pcToOffset.length; i++) {
                    if (pcToOffset[i]["pc"] >= pc) {
                        offset = pcToOffset[i]["offset"];
                        break;
                    }
                }

                if (i == pcToOffset.length) {
                    offset = pcToOffset[pcToOffset.length - 1]["offset"];
                }

                return disasm.substring(0, offset).split("\n").length - 1
            }

            // addExec({"pc":1,"stack":[{"t":"u"}],"scratch":[{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"},{"t":"u"}],"disasm":"// version 2\nintcblock 0 1\nbytecblock 0x68656c6c6f 0x7772697465 0x636865636b 0x666f6f 0x626172\ntxn ApplicationArgs 0\nbytec_0\n==\nbnz label1\ntxn ApplicationArgs 0\nbytec_1\n==\nbnz label2\ntxn ApplicationArgs 0\nbytec_2\n==\nintc_0\nintc_0\nbytec_3\napp_local_get\nintc_0\n==\nbnz label3\ntxn ApplicationArgs 1\n==\n\u0026\u0026\nintc_1\nbnz label4\nlabel2:\nintc_0\nbytec_3\nbytec 4\napp_local_put\nintc_1\nbnz label1\nlabel1:\nintc_1\nintc_1\nbnz label4\nlabel3:\nintc_0\nintc_1\nbnz label4\n","pctooffset":[{"pc":1,"offset":13},{"pc":5,"offset":27},{"pc":33,"offset":95},{"pc":36,"offset":117},{"pc":37,"offset":125},{"pc":38,"offset":128},{"pc":41,"offset":139},{"pc":44,"offset":161},{"pc":45,"offset":169},{"pc":46,"offset":172},{"pc":49,"offset":183},{"pc":52,"offset":205},{"pc":53,"offset":213},{"pc":54,"offset":216},{"pc":55,"offset":223},{"pc":56,"offset":230},{"pc":57,"offset":238},{"pc":58,"offset":252},{"pc":59,"offset":259},{"pc":60,"offset":262},{"pc":63,"offset":273},{"pc":66,"offset":295},{"pc":67,"offset":298},{"pc":68,"offset":301},{"pc":69,"offset":308},{"pc":72,"offset":327},{"pc":73,"offset":334},{"pc":74,"offset":342},{"pc":76,"offset":350},{"pc":77,"offset":364},{"pc":78,"offset":371},{"pc":81,"offset":390},{"pc":82,"offset":397},{"pc":83,"offset":404},{"pc":86,"offset":423},{"pc":87,"offset":430},{"pc":88,"offset":437}],"execid":"PD2HPDBATVA73GHR7LSPJA47SH53B7WZZVASTV3ETPAF7TEJBD6Q","error":""});

        </script>

        <script>
            const socket = new WebSocket('ws://localhost:9392/ws');

            socket.addEventListener('open', function (event) {
                socket.send('opened');
            });

            socket.addEventListener('message', function (event) {
                var msg = JSON.parse(event.data);

                if (msg["event"] !== "connected") {
                    document.getElementById("loading").style.display = "none";
                }

                if (msg["event"] === "registered") {
                    addExec(msg["state"])
                }

                if (msg["event"] === "updated" || msg["event"] === "completed") {
                    setExecContents(sessions[msg["state"]["execid"]], msg["state"]);
                }

                if (msg["event"] === "completed") {
                    delete sessions[msg["state"]["execid"]];
                }
            });
        </script>
    </body>
</html>
`
