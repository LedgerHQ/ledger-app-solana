import TransportNodeHid from "@ledgerhq/hw-transport-node-hid";
import { runSignTest } from "./core";

const run = async () => {
  try {
    await runSignTest(await TransportNodeHid.create());
    process.exit(0);
  } catch (e) {
    console.log(e);
    process.exit(1);
  }
};

run();
