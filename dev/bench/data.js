window.BENCHMARK_DATA = {
  "lastUpdate": 1653571639554,
  "repoUrl": "https://github.com/algorand/go-algorand",
  "entries": {
    "Go Benchmark": [
      {
        "commit": {
          "author": {
            "email": "86622919+algochoi@users.noreply.github.com",
            "name": "algochoi",
            "username": "algochoi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8bd8ab638214430c314c51a7869e0c874163360f",
          "message": "Tools: Add benchmark warnings for PRs and push graphs for commits into master (#3998)",
          "timestamp": "2022-05-19T14:08:58-04:00",
          "tree_id": "b9447c54c4e7ed44e1e7230eb2cd61d6d64c07c8",
          "url": "https://github.com/algorand/go-algorand/commit/8bd8ab638214430c314c51a7869e0c874163360f"
        },
        "date": 1652984050649,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkUintMath/dup",
            "value": 41.69,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "29080629 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop1",
            "value": 39.24,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "30263080 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop",
            "value": 76.25,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "15573020 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/add",
            "value": 80.36,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "15007250 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/addw",
            "value": 99.25,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12100771 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sub",
            "value": 80.98,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "15036736 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mul",
            "value": 80.65,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "14888068 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mulw",
            "value": 99.29,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12095306 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/div",
            "value": 89.82,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "13347735 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divw",
            "value": 135.6,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "8914254 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divmodw",
            "value": 895.3,
            "unit": "ns/op\t         8.000 extra/op\t     311 B/op\t      11 allocs/op",
            "extra": "1340305 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sqrt",
            "value": 93.64,
            "unit": "ns/op\t         2.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12806161 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/exp",
            "value": 118.9,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "10122567 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/expw",
            "value": 450.4,
            "unit": "ns/op\t         4.000 extra/op\t     110 B/op\t       5 allocs/op",
            "extra": "2670493 times\n2 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wwinder.unh@gmail.com",
            "name": "Will Winder",
            "username": "winder"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d06c9aa33d7cfdf55174dcc76b9465407fb05de9",
          "message": "use tag to determine channel if possible (#4017)",
          "timestamp": "2022-05-20T17:38:20-04:00",
          "tree_id": "6a94c6ee079847d1bfabbe142a21daf7fb3467b0",
          "url": "https://github.com/algorand/go-algorand/commit/d06c9aa33d7cfdf55174dcc76b9465407fb05de9"
        },
        "date": 1653082989772,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkUintMath/dup",
            "value": 44.56,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "26981827 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop1",
            "value": 40.57,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "29350918 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop",
            "value": 80.43,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "14952345 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/add",
            "value": 85.47,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "13970780 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/addw",
            "value": 107.3,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11222079 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sub",
            "value": 85.78,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "13917148 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mul",
            "value": 86.06,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "14137296 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mulw",
            "value": 106.9,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11107156 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/div",
            "value": 85.79,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "13966260 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divw",
            "value": 108.8,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11041188 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divmodw",
            "value": 886,
            "unit": "ns/op\t         8.000 extra/op\t     311 B/op\t      11 allocs/op",
            "extra": "1353211 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sqrt",
            "value": 101,
            "unit": "ns/op\t         2.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11901438 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/exp",
            "value": 94.32,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12799282 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/expw",
            "value": 433.6,
            "unit": "ns/op\t         4.000 extra/op\t     110 B/op\t       5 allocs/op",
            "extra": "2759766 times\n2 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "jannotti@gmail.com",
            "name": "John Jannotti",
            "username": "jannotti"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4a922c405f6847854e569a2624c97b7549078091",
          "message": "base64_decode can decode padded or unpadded encodings (#4015)",
          "timestamp": "2022-05-21T23:38:15-04:00",
          "tree_id": "ce698fe9f47c94e085b38a3f4c9e19cd6afe0f60",
          "url": "https://github.com/algorand/go-algorand/commit/4a922c405f6847854e569a2624c97b7549078091"
        },
        "date": 1653190991275,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkUintMath/dup",
            "value": 41.64,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "28389694 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop1",
            "value": 39.28,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "30792085 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop",
            "value": 77.74,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "15928520 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/add",
            "value": 80.42,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "14976067 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/addw",
            "value": 99.45,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12062668 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sub",
            "value": 80.83,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "14590981 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mul",
            "value": 80.43,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "14462902 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mulw",
            "value": 99.44,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11924718 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/div",
            "value": 90.24,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "13396202 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divw",
            "value": 136,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "8885370 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divmodw",
            "value": 898.7,
            "unit": "ns/op\t         8.000 extra/op\t     311 B/op\t      11 allocs/op",
            "extra": "1336909 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sqrt",
            "value": 94.14,
            "unit": "ns/op\t         2.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12827544 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/exp",
            "value": 119.2,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "10071489 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/expw",
            "value": 448.1,
            "unit": "ns/op\t         4.000 extra/op\t     110 B/op\t       5 allocs/op",
            "extra": "2677401 times\n2 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "91566643+algoidurovic@users.noreply.github.com",
            "name": "algoidurovic",
            "username": "algoidurovic"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b3e19e7c5f3bd1d25c624e18dd17f163ff7a8bc8",
          "message": "AVM: Allow immutable access to foreign app accounts (#3994)\n\n* allow foreign app accounts to be accessed (immutably)",
          "timestamp": "2022-05-23T14:40:31-04:00",
          "tree_id": "23e20648671b1830fe87dbcd25cc82b85a59b04a",
          "url": "https://github.com/algorand/go-algorand/commit/b3e19e7c5f3bd1d25c624e18dd17f163ff7a8bc8"
        },
        "date": 1653331520110,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkUintMath/dup",
            "value": 44.66,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "27151742 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop1",
            "value": 40.67,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "29470299 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop",
            "value": 79.81,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "15011929 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/add",
            "value": 85.48,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "13992582 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/addw",
            "value": 106.9,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11172351 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sub",
            "value": 85.77,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "14102131 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mul",
            "value": 85.22,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "14134071 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mulw",
            "value": 107.2,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11112448 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/div",
            "value": 85.94,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "13888563 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divw",
            "value": 108.5,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11026452 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divmodw",
            "value": 882.7,
            "unit": "ns/op\t         8.000 extra/op\t     311 B/op\t      11 allocs/op",
            "extra": "1360858 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sqrt",
            "value": 100.8,
            "unit": "ns/op\t         2.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11969226 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/exp",
            "value": 93.92,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12678433 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/expw",
            "value": 433.3,
            "unit": "ns/op\t         4.000 extra/op\t     110 B/op\t       5 allocs/op",
            "extra": "2759246 times\n2 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "jannotti@gmail.com",
            "name": "John Jannotti",
            "username": "jannotti"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8088e04b523f44a1a304fd2c83afbf7ae875dcb6",
          "message": "AVM: Add bn256 pairing opcodes experimentally (#4013)\n\n* add bn256 add, scalar multiply and pairing opcode\r\n* replace with gnark bn254 and bench\r\n* update opcost for bn256 according to benchmark\r\n\r\n\r\nSome doc tweaks, and moved implementation to pairing.go\r\n\r\nThese opcodes should stay in vFuture until\r\n\r\n1. We consider the serialization format\r\n2. We have unit tests\r\n3. We consider BLS 12-381 (and the opcodes of eip 2537)\r\n4. Audit of gnark-crypto library\r\n\r\nCo-authored-by: Bo Yao <by677@nyu.edu>\r\nCo-authored-by: Bo Yao <bo@abstrlabs.com>\r\nCo-authored-by: bo-abstrlabs <96916614+bo-abstrlabs@users.noreply.github.com>\r\nCo-authored-by: chris erway <chris.erway@algorand.com>",
          "timestamp": "2022-05-24T09:14:01-04:00",
          "tree_id": "995f998c4483b01f1e259fe4ac9a5674756b0026",
          "url": "https://github.com/algorand/go-algorand/commit/8088e04b523f44a1a304fd2c83afbf7ae875dcb6"
        },
        "date": 1653398355330,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkUintMath/dup",
            "value": 44.98,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "28609860 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop1",
            "value": 39.51,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "30035172 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop",
            "value": 77.97,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "15885462 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/add",
            "value": 81.74,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "14931496 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/addw",
            "value": 100.2,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12014640 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sub",
            "value": 82.06,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "14348632 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mul",
            "value": 81.57,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "14698472 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mulw",
            "value": 101.9,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11870779 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/div",
            "value": 91.01,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "13084359 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divw",
            "value": 135.8,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "8835219 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divmodw",
            "value": 945.6,
            "unit": "ns/op\t         8.000 extra/op\t     311 B/op\t      11 allocs/op",
            "extra": "1278649 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sqrt",
            "value": 95.22,
            "unit": "ns/op\t         2.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12700041 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/exp",
            "value": 119.5,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "10075036 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/expw",
            "value": 449.9,
            "unit": "ns/op\t         4.000 extra/op\t     110 B/op\t       5 allocs/op",
            "extra": "2681427 times\n2 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "51567+cce@users.noreply.github.com",
            "name": "cce",
            "username": "cce"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "280102c72ec9e6c106724dabdd6a57eeec1072f0",
          "message": "metrics: make metrics easier to use with prometheus (#4020)\n\n* make TagCounter metrics easier to use with prometheus\r\n\r\n* ensure 0 counters are logged\r\n\r\n* allow for pre-declaring TagCounter tags for use with prometheus\r\n\r\n* fix expected in TestTagCounterWriteMetric\r\n\r\n* deregister counter used in test\r\n\r\n* fix lint warning\r\n\r\n* CR comment\r\n\r\n* Log incorrect metrics for debugging test failures\r\n\r\n* deregister more counters and tagcounters used by tests\r\n\r\n* remove unused Segment",
          "timestamp": "2022-05-24T17:05:00-04:00",
          "tree_id": "e7a2b720eeebb07f0fe78b610906e0e2a55f9c88",
          "url": "https://github.com/algorand/go-algorand/commit/280102c72ec9e6c106724dabdd6a57eeec1072f0"
        },
        "date": 1653426621699,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkUintMath/dup",
            "value": 52.19,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "22029985 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop1",
            "value": 46.22,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "27000336 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop",
            "value": 90.95,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "13725756 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/add",
            "value": 95.45,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12938955 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/addw",
            "value": 119,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "10481948 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sub",
            "value": 98.69,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12230994 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mul",
            "value": 97.32,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11498259 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mulw",
            "value": 123.8,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "9882183 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/div",
            "value": 102,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11708571 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divw",
            "value": 151.4,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "8107504 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divmodw",
            "value": 978.7,
            "unit": "ns/op\t         8.000 extra/op\t     310 B/op\t      11 allocs/op",
            "extra": "1217941 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sqrt",
            "value": 106.7,
            "unit": "ns/op\t         2.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11934229 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/exp",
            "value": 137.4,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "8446070 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/expw",
            "value": 536.8,
            "unit": "ns/op\t         4.000 extra/op\t     110 B/op\t       5 allocs/op",
            "extra": "2346409 times\n2 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "brianolson@users.noreply.github.com",
            "name": "Brian Olson",
            "username": "brianolson"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3c4c8fb0bd7a0632453ded8130156f58026e287c",
          "message": "network: non-participating nodes request TX gossip only if ForceFetchTransactions: true (#3918)\n\nSave bandwidth by having non-participating non-relay nodes\r\nopt-out of TX transaction gossip traffic using message-of-interest.\r\nTo enable set localConfig.ForceFetchTransactions = true\r\n\r\nManual testing has started local private networks to ensure\r\nthat the new message-of-interest propagated.\r\nCluster tests were run to check bandwidth usage.\r\n\r\nCo-authored-by: cce <51567+cce@users.noreply.github.com>",
          "timestamp": "2022-05-24T21:49:18-04:00",
          "tree_id": "a70436ffe17b161ef02740cda023d2a01335da3c",
          "url": "https://github.com/algorand/go-algorand/commit/3c4c8fb0bd7a0632453ded8130156f58026e287c"
        },
        "date": 1653443662959,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkUintMath/dup",
            "value": 43,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "28987072 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop1",
            "value": 39.25,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "30019779 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop",
            "value": 76.45,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "15743168 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/add",
            "value": 81,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "14874644 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/addw",
            "value": 103,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12017370 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sub",
            "value": 81.54,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "14487516 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mul",
            "value": 81.78,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "14693922 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mulw",
            "value": 99.94,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12068809 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/div",
            "value": 90.15,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "13246796 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divw",
            "value": 137.4,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "8816834 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divmodw",
            "value": 918.6,
            "unit": "ns/op\t         8.000 extra/op\t     311 B/op\t      11 allocs/op",
            "extra": "1330746 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sqrt",
            "value": 93.93,
            "unit": "ns/op\t         2.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12873868 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/exp",
            "value": 119.1,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "10119730 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/expw",
            "value": 445.8,
            "unit": "ns/op\t         4.000 extra/op\t     110 B/op\t       5 allocs/op",
            "extra": "2680022 times\n2 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "lucky.baar@algorand.com",
            "name": "algolucky",
            "username": "algolucky"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c9f4151785d0328155dc793465544b8f13166a64",
          "message": " fix: place updater in same directory as update.sh and add verify option (#3983)",
          "timestamp": "2022-05-25T09:47:34-04:00",
          "tree_id": "219ecbe3abd6ab320151a9971e0c7be7dbf89ff5",
          "url": "https://github.com/algorand/go-algorand/commit/c9f4151785d0328155dc793465544b8f13166a64"
        },
        "date": 1653486838800,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkUintMath/dup",
            "value": 57.03,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "21526094 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop1",
            "value": 54.72,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "23018557 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop",
            "value": 100.4,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11786556 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/add",
            "value": 108.3,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11127818 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/addw",
            "value": 134,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "8538868 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sub",
            "value": 108.8,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11061420 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mul",
            "value": 109.4,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11237280 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mulw",
            "value": 137.7,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "9094478 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/div",
            "value": 119.6,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "9843416 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divw",
            "value": 174,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "6880671 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divmodw",
            "value": 1197,
            "unit": "ns/op\t         8.000 extra/op\t     311 B/op\t      11 allocs/op",
            "extra": "916680 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sqrt",
            "value": 120.6,
            "unit": "ns/op\t         2.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "9933202 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/exp",
            "value": 155.5,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "7760907 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/expw",
            "value": 601.6,
            "unit": "ns/op\t         4.000 extra/op\t     110 B/op\t       5 allocs/op",
            "extra": "2006352 times\n2 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "nullun@users.noreply.github.com",
            "name": "nullun",
            "username": "nullun"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2df7468fa4ef71fefceff4ab1688c8badb3d1464",
          "message": "Added generate-docs command to tealdbg (#3830)\n\nWhen generating the CLI documentation for the Developer Portal\r\nit was noticed that tealdbg was missing. Much like goal, kmd, and algokey,\r\nadded the \"generate-docs\" command option to generate the markdown output.",
          "timestamp": "2022-05-25T10:43:23-04:00",
          "tree_id": "a2571ab66abe2459fd2179610bad883feea3e135",
          "url": "https://github.com/algorand/go-algorand/commit/2df7468fa4ef71fefceff4ab1688c8badb3d1464"
        },
        "date": 1653490178261,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkUintMath/dup",
            "value": 53.27,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "23386305 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop1",
            "value": 52.53,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "25127174 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop",
            "value": 94.33,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12265256 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/add",
            "value": 99.93,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11995268 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/addw",
            "value": 127.2,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "9476030 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sub",
            "value": 100.6,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12449613 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mul",
            "value": 99.79,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12415094 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mulw",
            "value": 126.6,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "8549336 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/div",
            "value": 110.7,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "10864909 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divw",
            "value": 164.1,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "7401888 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divmodw",
            "value": 1060,
            "unit": "ns/op\t         8.000 extra/op\t     311 B/op\t      11 allocs/op",
            "extra": "1136058 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sqrt",
            "value": 109.9,
            "unit": "ns/op\t         2.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11177181 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/exp",
            "value": 147.8,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "8196412 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/expw",
            "value": 553.4,
            "unit": "ns/op\t         4.000 extra/op\t     110 B/op\t       5 allocs/op",
            "extra": "2180550 times\n2 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "or.aharonee@algorand.com",
            "name": "Or Aharonee",
            "username": "Aharonee"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a3003ec5668d20e81c9b1d24b09dfaf8eff524fc",
          "message": "Add missing HashType to GetProof endpoint (#3985)",
          "timestamp": "2022-05-26T09:21:32-04:00",
          "tree_id": "eedab762bca0d359fba2825232ff0a0ac666134b",
          "url": "https://github.com/algorand/go-algorand/commit/a3003ec5668d20e81c9b1d24b09dfaf8eff524fc"
        },
        "date": 1653571638669,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkUintMath/dup",
            "value": 52.54,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "22163901 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop1",
            "value": 49.88,
            "unit": "ns/op\t         1.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "27039301 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/pop",
            "value": 95.39,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12993996 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/add",
            "value": 103.6,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "12384310 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/addw",
            "value": 134,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "9018788 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sub",
            "value": 104.2,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11546125 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mul",
            "value": 106.3,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "11183803 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/mulw",
            "value": 131.3,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "8616392 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/div",
            "value": 111.9,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "10945590 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divw",
            "value": 165.7,
            "unit": "ns/op\t         4.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "6938215 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/divmodw",
            "value": 1087,
            "unit": "ns/op\t         8.000 extra/op\t     311 B/op\t      11 allocs/op",
            "extra": "1123218 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/sqrt",
            "value": 112.5,
            "unit": "ns/op\t         2.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "10796629 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/exp",
            "value": 144.5,
            "unit": "ns/op\t         3.000 extra/op\t       6 B/op\t       0 allocs/op",
            "extra": "8415711 times\n2 procs"
          },
          {
            "name": "BenchmarkUintMath/expw",
            "value": 568.2,
            "unit": "ns/op\t         4.000 extra/op\t     110 B/op\t       5 allocs/op",
            "extra": "2107562 times\n2 procs"
          }
        ]
      }
    ]
  }
}