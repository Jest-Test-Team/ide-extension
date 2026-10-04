using BenchmarkTools
using InvDemo

const SUITE = BenchmarkGroup()
SUITE["process"] = BenchmarkGroup()
SUITE["process"]["float"] = @benchmarkable InvDemo.process(x) setup = (x = rand(100))
SUITE["process"]["range"] = @benchmarkable InvDemo.process(1:100)
