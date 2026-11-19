import { render,screen,within,waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach,expect,it } from "vitest";
import { fakeApi } from "./testing";
import { ExitLatencyPanel } from "./ExitLatency";
afterEach(()=>sessionStorage.clear());
const sample={exit_id:"us",name:"美国出口",scope:"exit_resolver",state:"ok",rtt_ms:135.25,sent:3,received:3,measured_at:"2026-11-19T04:00:00Z",stale:false};
it("shows gateway RTT and never invents zero for an unreachable exit",async()=>{
 fakeApi({"GET /api/exits/latency":()=>({available:true,running:false,rows:[sample,{...sample,exit_id:"hk",name:"香港",state:"unreachable",rtt_ms:undefined,received:0}]})});
 render(<ExitLatencyPanel/>);
 expect(await screen.findByText("135.3 ms")).toBeInTheDocument();
 const fail=screen.getByTestId("exit-latency-hk");expect(fail).toHaveTextContent("未连通");expect(fail).not.toHaveTextContent("0.0 ms");
});
it("measures unmeasured exits once and explains the external SOCKS boundary",async()=>{
 const a=fakeApi({"GET /api/exits/latency":()=>({available:true,running:false,rows:[{...sample,state:"not_measured",rtt_ms:undefined}]}),"POST /api/exits/latency":()=>({available:true,running:false,rows:[{...sample,scope:"carrier_resolver"}]})});
 render(<ExitLatencyPanel/>);
 expect(await screen.findByText("外部 SOCKS：仅到承载节点解析器")).toBeInTheDocument();
 expect(a.find("POST /api/exits/latency")).toHaveLength(1);
 await userEvent.click(screen.getByRole("button",{name:/测量延迟/}));
 await waitFor(()=>expect(a.find("POST /api/exits/latency")).toHaveLength(2));
 expect(within(screen.getByTestId("exit-latency-us")).getByText("135.3 ms")).toBeInTheDocument();
});
