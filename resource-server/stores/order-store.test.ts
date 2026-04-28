import assert from "node:assert/strict";
import test from "node:test";
import { createOrderStore } from "./order-store.ts";

test("createOrderStore starts empty by default", function () {
  const orderStore = createOrderStore();

  assert.deepEqual(orderStore.getOrdersByUserId("missing-user-id"), []);
  assert.equal(orderStore.getOrderById("missing-order-id"), undefined);
});

test("createOrderStore allows loading orders by id and user id", function () {
  const orderStore = createOrderStore([
    { orderId: "existing-order-id", userId: "existing-user-id" },
    { orderId: "other-order-id", userId: "other-user-id" },
  ]);
  const existingUserOrders = orderStore.getOrdersByUserId("existing-user-id");

  assert.deepEqual(existingUserOrders, [
    { orderId: "existing-order-id", userId: "existing-user-id" },
  ]);
  assert.equal(
    orderStore.getOrderById("existing-order-id"),
    existingUserOrders[0],
  );
  assert.deepEqual(orderStore.getOrdersByUserId("missing-user-id"), []);
});

test("getOrdersByUserId returns a copy of matching orders", function () {
  const orderStore = createOrderStore([
    { orderId: "existing-order-id", userId: "existing-user-id" },
  ]);
  const existingUserOrders = orderStore.getOrdersByUserId("existing-user-id");

  existingUserOrders.push({
    orderId: "extra-order-id",
    userId: "existing-user-id",
  });

  assert.deepEqual(orderStore.getOrdersByUserId("existing-user-id"), [
    { orderId: "existing-order-id", userId: "existing-user-id" },
  ]);
});
