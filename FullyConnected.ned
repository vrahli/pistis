//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.orgaggregateSet/licenses/.
// 

//package pistis;

simple Process {
    parameters:
        @display("i=block/routing");
        @signal[outBdw](type="long");
        @statistics[outBandwidth](source=outBdw; record=vector, stats);
         int timeout         @unit(ms);
         int maxDelay        @unit(ms);
         bool rtByzCastMode    = default(false); // must be true to run in RT-ByzCast mode, by default we don't run in RT-ByzCastMode
         int passiveDuration   = default(10);    // a multiple of maxDelay
         int maxFaults;                          // total number of faults
         int numRand;                            // fanout: number of nodes to send messages to
         int numBcaster        = default(1);     // by default only 1 node broadcasts messages
         int numBcast          = default(1);     // only 1 broadcast by default
         int bcastPeriod       = default(3);     // a broadcasting node only broadcasts messages everty 3*timeout by default
         bool GC               = default(true);  // garbage collection is turned on by default
         int probaLosses       = default(0);     // no message losses by default
         int sizeVal           = default(1);     // size of a value in bytes
         int numPassive        = default(0);     // no passive nodes by default
         int numByz            = default(0);     // no initially Byzantine nodes by default
         bool recovery         = default(false); // recovery is turned off by default
         bool lossSend         = default(false); // by default we drop messages when we receive them, not when we send them
         bool rotatingSend     = default(false); // by default we send messages at random, not by rotating through the nodes
         bool endSimuDeliver   = default(false); // by default we don't end the simulation after the last deliver
         bool stopEarly        = default(false); // by default we don't stop early (meaning when a quorum delivered) - this is only used for debugging
		 bool clear            = default(true);  // to clear the memory when finishing
         string passiveOutput  = default("stats/file");
         string durationOutput = default("stats/duration");
         string statsOutput    = default("debugStats");
    gates:
        inout gate[];
}

network FullyConnected {
    parameters:
         int maxFaults; // This is supposed to be the same as Process.maxFaults
         int n = (3 * maxFaults) + 1;
         volatile double mean   @unit(ms);// = default(0ms);
         volatile double stddev @unit(ms);// = default(0ms);
         //volatile double Delay  @unit(ms) = truncnormal(mean, stddev);
    types:
        channel Channel extends ned.DatarateChannel { //ned.DelayChannel {
            delay = truncnormal(mean, stddev); // the max transmission delay is 20ms (mean,standard deviation)
            datarate = 10000000000 bps;
           	//datarate = 5700000bps;
            // WTF!  This doesn't seem to be doing anything...
            //ber = 1; // 1e-10; // bit rate error
            //per = 1; // 1e-10; // packet rate error
        }
    submodules:
        p[n]: Process;
    connections allowunconnected:
        for i=0..(n-2), for j=(i+1)..(n-1) {
            p[i].gate++ <--> Channel <--> p[j].gate++;
        }
}
