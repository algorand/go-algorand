// Copyright (C) 2019-2020 Algorand, Inc.
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

package cdt

// definitions copied from packages below with json fields and struct names fixed
// "github.com/wirepair/gcd/gcdapi"
// "github.com/wirepair/gcd/gcdmessage"

// ChromeResponse is default response object, contains the id and a result if applicable.
type ChromeResponse struct {
	ID     int64       `json:"id"`
	Result interface{} `json:"result"`
}

// ChromeRequest is default no-arg request
type ChromeRequest struct {
	ID     int64       `json:"id"`
	Method string      `json:"method"`
	Params interface{} `json:"params,omitempty"`
}

// TabDescription represents information shown by CDT at chrome://inspect/ tab
type TabDescription struct {
	Description               string `json:"description"`
	DevtoolsFrontendURL       string `json:"devtoolsFrontendUrl"`
	ID                        string `json:"id"`
	Title                     string `json:"title"`
	TabType                   string `json:"type"`
	URL                       string `json:"url"`
	WebSocketDebuggerURL      string `json:"webSocketDebuggerUrl"`
	DevtoolsFrontendURLCompat string `json:"devtoolsFrontendUrlCompat"`
	FaviconURL                string `json:"faviconUrl"`
}

// RuntimeStackTraceID type
type RuntimeStackTraceID struct {
	ID         string `json:"id"`                   //
	DebuggerID string `json:"debuggerId,omitempty"` //
}

// RuntimeCallFrame type
type RuntimeCallFrame struct {
	FunctionName string `json:"functionName"` // JavaScript function name.
	ScriptID     string `json:"scriptId"`     // JavaScript script id.
	URL          string `json:"url"`          // JavaScript script name or url.
	LineNumber   int    `json:"lineNumber"`   // JavaScript script line number (0-based).
	ColumnNumber int    `json:"columnNumber"` // JavaScript script column number (0-based).
}

// RuntimeStackTrace type
type RuntimeStackTrace struct {
	Description string               `json:"description,omitempty"` // String label of this stack trace. For async traces this may be a name of the function that initiated the async call.
	CallFrames  []*RuntimeCallFrame  `json:"callFrames"`            // JavaScript function name.
	Parent      *RuntimeStackTrace   `json:"parent,omitempty"`      // Asynchronous JavaScript stack trace that preceded this stack, if available.
	ParentID    *RuntimeStackTraceID `json:"parentId,omitempty"`    // Asynchronous JavaScript stack trace that preceded this stack, if available.
}

// RuntimeExecutionContextDescription type
type RuntimeExecutionContextDescription struct {
	ID      int                    `json:"id"`                // Unique id of the execution context. It can be used to specify in which execution context script evaluation should be performed.
	Origin  string                 `json:"origin"`            // Execution context origin.
	Name    string                 `json:"name"`              // Human readable name describing given context.
	AuxData map[string]interface{} `json:"auxData,omitempty"` // Embedder-specific auxiliary data.
}

// RuntimeExecutionContextCreatedParams type
type RuntimeExecutionContextCreatedParams struct {
	Context RuntimeExecutionContextDescription `json:"context"` // A newly created execution context.
}

// RuntimeExecutionContextCreatedEvent issued when new execution context is created.
type RuntimeExecutionContextCreatedEvent struct {
	Method string                               `json:"method"`
	Params RuntimeExecutionContextCreatedParams `json:"params,omitempty"`
}

// RuntimeExecutionContextDestroyedParams type
type RuntimeExecutionContextDestroyedParams struct {
	ExecutionContextID int `json:"executionContextId"` // Id of the destroyed context
}

// RuntimeExecutionContextDestroyedEvent issued when execution context is destroyed.
type RuntimeExecutionContextDestroyedEvent struct {
	Method string                                 `json:"method"`
	Params RuntimeExecutionContextDestroyedParams `json:"params,omitempty"`
}

// RuntimeRemoteObject is mirror object referencing original JavaScript object.
type RuntimeRemoteObject struct {
	Type                string                `json:"type"`                          // Object type.
	Subtype             string                `json:"subtype,omitempty"`             // Object subtype hint. Specified for `object` type values only.
	ClassName           string                `json:"className,omitempty"`           // Object class (constructor) name. Specified for `object` type values only.
	Value               interface{}           `json:"value,omitempty"`               // Remote object value in case of primitive values or JSON values (if it was requested).
	UnserializableValue string                `json:"unserializableValue,omitempty"` // Primitive value which can not be JSON-stringified does not have `value`, but gets this property.
	Description         string                `json:"description,omitempty"`         // String representation of the object.
	ObjectID            string                `json:"objectId,omitempty"`            // Unique object identifier (for non-primitive values).
	Preview             *RuntimeObjectPreview `json:"preview,omitempty"`             // Preview containing abbreviated property values. Specified for `object` type values only.
	CustomPreview       *RuntimeCustomPreview `json:"customPreview,omitempty"`       //
}

// RuntimeCustomPreview type
type RuntimeCustomPreview struct {
	Header       string `json:"header"`                 // The JSON-stringified result of formatter.header(object, config) call. It contains json ML array that represents RemoteObject.
	BodyGetterID string `json:"bodyGetterId,omitempty"` // If formatter returns true as a result of formatter.hasBody call then bodyGetterId will contain RemoteObjectId for the function that returns result of formatter.body(object, config) call. The result value is json ML array.
}

// RuntimeObjectPreview is an object containing abbreviated remote object value.
type RuntimeObjectPreview struct {
	Type        string                   `json:"type"`                  // Object type.
	Subtype     string                   `json:"subtype,omitempty"`     // Object subtype hint. Specified for `object` type values only.
	Description string                   `json:"description,omitempty"` // String representation of the object.
	Overflow    bool                     `json:"overflow"`              // True iff some of the properties or entries of the original object did not fit.
	Properties  []RuntimePropertyPreview `json:"properties"`            // List of the properties.
	Entries     []RuntimeEntryPreview    `json:"entries,omitempty"`     // List of the entries. Specified for `map` and `set` subtype values only.
}

// RuntimePropertyPreview type
type RuntimePropertyPreview struct {
	Name         string                `json:"name"`                   // Property name.
	Type         string                `json:"type"`                   // Object type. Accessor means that the property itself is an accessor property.
	Value        string                `json:"value,omitempty"`        // User-friendly property value string.
	ValuePreview *RuntimeObjectPreview `json:"valuePreview,omitempty"` // Nested value preview.
	Subtype      string                `json:"subtype,omitempty"`      // Object subtype hint. Specified for `object` type values only.
}

// RuntimeEntryPreview type
type RuntimeEntryPreview struct {
	Key   RuntimeObjectPreview `json:"key,omitempty"` // Preview of the key. Specified for map-like collection entries.
	Value RuntimeObjectPreview `json:"value"`         // Preview of the value.
}

// RuntimePropertyDescriptor is object property descriptor.
type RuntimePropertyDescriptor struct {
	Name         string               `json:"name"`                // Property name or symbol description.
	Value        *RuntimeRemoteObject `json:"value,omitempty"`     // The value associated with the property.
	Writable     bool                 `json:"writable"`            // True if the value associated with the property may be changed (data descriptors only).
	Get          *RuntimeRemoteObject `json:"get,omitempty"`       // A function which serves as a getter for the property, or `undefined` if there is no getter (accessor descriptors only).
	Set          *RuntimeRemoteObject `json:"set,omitempty"`       // A function which serves as a setter for the property, or `undefined` if there is no setter (accessor descriptors only).
	Configurable bool                 `json:"configurable"`        // True if the type of this property descriptor may be changed and if the property may be deleted from the corresponding object.
	Enumerable   bool                 `json:"enumerable"`          // True if this property shows up during enumeration of the properties on the corresponding object.
	WasThrown    bool                 `json:"wasThrown,omitempty"` // True if the result was thrown during the evaluation.
	IsOwn        bool                 `json:"isOwn,omitempty"`     // True if the property is owned for the object.
	Symbol       *RuntimeRemoteObject `json:"symbol,omitempty"`    // Property symbol object, if the property is of the `symbol` type.
}

// RuntimeCallArgument represents function call argument. Either remote object id `objectId`, primitive `value`, unserializable primitive value or neither of (for undefined) them should be specified.
type RuntimeCallArgument struct {
	Value               interface{} `json:"value,omitempty"`               // Primitive value or serializable javascript object.
	UnserializableValue string      `json:"unserializableValue,omitempty"` // Primitive value which can not be JSON-stringified.
	ObjectID            string      `json:"objectId,omitempty"`            // Remote object handle.
}

// RuntimeCallPackRangesObject is packRanges response object
type RuntimeCallPackRangesObject struct {
	Type  string                     `json:"type,omitempty"`
	Value RuntimeCallPackRangesRange `json:"value,omitempty"`
}

// RuntimeCallPackRangesRange range object
type RuntimeCallPackRangesRange struct {
	Ranges [][3]int `json:"ranges,omitempty"`
}

// DebuggerScriptParsedParams type
type DebuggerScriptParsedParams struct {
	ScriptID                string                 `json:"scriptId"`                          // Identifier of the script parsed.
	URL                     string                 `json:"url"`                               // URL or name of the script parsed (if any).
	StartLine               int                    `json:"startLine"`                         // Line offset of the script within the resource with given URL (for script tags).
	StartColumn             int                    `json:"startColumn"`                       // Column offset of the script within the resource with given URL.
	EndLine                 int                    `json:"endLine"`                           // Last line of the script.
	EndColumn               int                    `json:"endColumn"`                         // Length of the last line of the script.
	ExecutionContextID      int                    `json:"executionContextId"`                // Specifies script creation context.
	Hash                    string                 `json:"hash"`                              // Content hash of the script.
	ExecutionContextAuxData map[string]interface{} `json:"executionContextAuxData,omitempty"` // Embedder-specific auxiliary data.
	IsLiveEdit              bool                   `json:"isLiveEdit,omitempty"`              // True, if this script is generated as a result of the live edit operation.
	SourceMapURL            string                 `json:"sourceMapURL,omitempty"`            // URL of source map associated with script (if any).
	HasSourceURL            bool                   `json:"hasSourceURL,omitempty"`            // True, if this script has sourceURL.
	IsModule                bool                   `json:"isModule,omitempty"`                // True, if this script is ES6 module.
	Length                  int                    `json:"length,omitempty"`                  // This script length.
	StackTrace              RuntimeStackTrace      `json:"stackTrace,omitempty"`              // JavaScript top stack frame of where the script parsed event was triggered if available.
}

// DebuggerScriptParsedEvent type
type DebuggerScriptParsedEvent struct {
	Method string                     `json:"method"`
	Params DebuggerScriptParsedParams `json:"params,omitempty"`
}

// DebuggerLocation is location in the source code.
type DebuggerLocation struct {
	ScriptID     string `json:"scriptId"`     // Script identifier as reported in the `Debugger.scriptParsed`.
	LineNumber   int    `json:"lineNumber"`   // Line number in the script (0-based).
	ColumnNumber int    `json:"columnNumber"` // Column number in the script (0-based).
}

// DebuggerContinueToLocationParams type
type DebuggerContinueToLocationParams struct {
	// Location to continue to.
	Location DebuggerLocation `json:"location"`
	//
	TargetCallFrames string `json:"targetCallFrames,omitempty"`
}

// DebuggerCallFrame is JavaScript call frame. Array of call frames form the call stack.
type DebuggerCallFrame struct {
	CallFrameID      string               `json:"callFrameId"`                // Call frame identifier. This identifier is only valid while the virtual machine is paused.
	FunctionName     string               `json:"functionName"`               // Name of the JavaScript function called on this call frame.
	FunctionLocation *DebuggerLocation    `json:"functionLocation,omitempty"` // Location in the source code.
	Location         *DebuggerLocation    `json:"location"`                   // Location in the source code.
	URL              string               `json:"url"`                        // JavaScript script name or url.
	ScopeChain       []DebuggerScope      `json:"scopeChain"`                 // Scope chain for this call frame.
	This             *RuntimeRemoteObject `json:"this"`                       // `this` object for this call frame.
	ReturnValue      *RuntimeRemoteObject `json:"returnValue,omitempty"`      // The value being returned, if the function is at return point.
}

// DebuggerScope description.
type DebuggerScope struct {
	Type          string              `json:"type"`                    // Scope type.
	Object        RuntimeRemoteObject `json:"object"`                  // Object representing the scope. For `global` and `with` scopes it represents the actual object; for the rest of the scopes, it is artificial transient object enumerating scope variables as its properties.
	Name          string              `json:"name,omitempty"`          //
	StartLocation *DebuggerLocation   `json:"startLocation,omitempty"` // Location in the source code where scope starts
	EndLocation   *DebuggerLocation   `json:"endLocation,omitempty"`   // Location in the source code where scope ends
}

// DebuggerPausedParams type
type DebuggerPausedParams struct {
	CallFrames            []DebuggerCallFrame    `json:"callFrames"`                      // Call stack the virtual machine stopped on.
	Reason                string                 `json:"reason"`                          // Pause reason.
	Data                  map[string]interface{} `json:"data,omitempty"`                  // Object containing break-specific auxiliary properties.
	HitBreakpoints        []string               `json:"hitBreakpoints"`                  // Hit breakpoints IDs
	AsyncStackTrace       *RuntimeStackTrace     `json:"asyncStackTrace,omitempty"`       // Async stack trace, if any.
	AsyncStackTraceID     *RuntimeStackTraceID   `json:"asyncStackTraceId,omitempty"`     // Async stack trace, if any.
	AsyncCallStackTraceID *RuntimeStackTraceID   `json:"asyncCallStackTraceId,omitempty"` // Just scheduled async call will have this stack trace as parent stack during async execution. This field is available only after `Debugger.stepInto` call with `breakOnAsynCall` flag.
}

// DebuggerPausedEvent is fired when the virtual machine stopped on breakpoint or exception or any other stop criteria.
type DebuggerPausedEvent struct {
	Method string               `json:"method"`
	Params DebuggerPausedParams `json:"params,omitempty"`
}
