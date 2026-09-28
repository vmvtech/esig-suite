import { expect, it } from "vitest";

import * as reactExports from "../src/index.js";

it("exports the public React components", () => {
  expect(Object.keys(reactExports).sort()).toEqual([
    "SelfSignFlow",
    "SelfSignedReceipt",
    "SignaturePadCanvas",
    "VerifyPanel",
  ]);
});
