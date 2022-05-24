window.BENCHMARK_DATA = {
  "lastUpdate": 1653398355872,
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
      }
    ]
  }
}