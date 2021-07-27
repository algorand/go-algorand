package test

// used to generate code that might produce this error:
//
//         	Error:      	Received unexpected error:
//        	            	msgp: length overflow: 29 > 16
//        	Test:       	TestRandomizedEncodingtestSlice

//msgp:allocbound testSlice 16
type testSlice []uint64
