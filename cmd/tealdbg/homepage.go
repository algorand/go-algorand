// Copyright (C) 2019-2021 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

// Code generated during build process. DO NOT EDIT.
package main

var homepage string = `
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
            const TealBytesType = 1;
            const TealUintType = 2;
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

                    type.innerText = values[i].tt == TealUintType ? "u": "b";
                    if (values[i].tt === TealUintType) {
                        value.innerText = values[i].ui || 0;
                    } else {
                        value.innerText = values[i].tb || "";
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

                var highlightLine = state["line"]
                var rows = codetable.querySelectorAll("tr");
                rows[highlightLine].classList.toggle("green", true);

                var codewrapper = exec.querySelector(".codewrapper");

                // Scroll hit line into view
                if ((codewrapper.scrollTop + codewrapper.offsetHeight) < rows[highlightLine].offsetTop) {
                    codewrapper.scrollTop = rows[highlightLine].offsetTop;
                }

                var buttonHandler = function(singlestep) {
                    return function() {
                        if (singlestep) {
                            // Tell server to notify us on this PC
                            let req = new XMLHttpRequest();
                            req.open("POST", "/exec/step", false);
                            req.setRequestHeader("Content-Type", "application/json");
                            req.send(JSON.stringify({"execid": state["execid"], "breakatline": 0}));
                            return
                        }
                        // Iterate over breakpoints and find the next one greater
                        // than the current line. If none, don't break at all (-1).
                        let breakLine = -1;
                        var checkboxes = exec.querySelectorAll("input");
                        for (var i = state["line"] + 1; i < checkboxes.length; i++) {
                            if (checkboxes[i].checked) {
                                breakLine = i
                                break
                            }
                        }

                        // Tell server to notify us on this PC
                        var req = new XMLHttpRequest();
                        req.open("POST", "/exec/config", false);
                        req.setRequestHeader("Content-Type", "application/json");
                        req.send(JSON.stringify({"execid": state["execid"], "breakatline": breakLine}));

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
