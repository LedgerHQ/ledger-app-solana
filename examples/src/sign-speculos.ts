import SpeculosTransport from "@ledgerhq/hw-transport-node-speculos";
import { runSignTest } from "./core";

const APDU_PORT = 9999;

const run = async () => {
  try {
    await runSignTest(await SpeculosTransport.open({ apduPort: APDU_PORT }));
    process.exit(0);
  } catch (e) {
    console.log(e);
    process.exit(1);
  }
};

run();
