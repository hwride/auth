import assert from "node:assert/strict";
import test from "node:test";
import {
  createDefaultProductStore,
  createProductStore,
} from "./product-store.ts";

test("createProductStore starts empty by default", function () {
  const productStore = createProductStore();

  assert.deepEqual(productStore.getProductsAll(), []);
  assert.equal(productStore.getProductById("product-001"), undefined);
});

test("getProductsAll returns a copy of all products", function () {
  const productStore = createDefaultProductStore();

  const products = productStore.getProductsAll();
  products.push({ productId: "product-999", name: "Extra product" });

  assert.deepEqual(productStore.getProductsAll(), [
    { productId: "product-001", name: "Keyboard" },
    { productId: "product-002", name: "Mouse" },
  ]);
});

test("createDefaultProductStore allows loading seeded products by id", function () {
  const productStore = createDefaultProductStore();

  assert.deepEqual(productStore.getProductById("product-001"), {
    productId: "product-001",
    name: "Keyboard",
  });
  assert.deepEqual(productStore.getProductById("product-002"), {
    productId: "product-002",
    name: "Mouse",
  });
  assert.equal(productStore.getProductById("product-999"), undefined);
});
