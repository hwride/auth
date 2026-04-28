export type OrderRecord = {
  orderId: string;
  userId: string;
};

export type OrderStore = {
  getOrdersByUserId(userId: string): OrderRecord[];
  getOrderById(orderId: string): OrderRecord | undefined;
};

export function createOrderStore(
  initialOrders: OrderRecord[] = [],
): OrderStore {
  const ordersById = new Map(
    initialOrders.map(function (order) {
      return [order.orderId, order];
    }),
  );
  const ordersByUserId = new Map<string, OrderRecord[]>();

  for (const order of initialOrders) {
    const userOrders = ordersByUserId.get(order.userId) ?? [];
    userOrders.push(order);
    ordersByUserId.set(order.userId, userOrders);
  }

  return {
    getOrdersByUserId(userId) {
      return [...(ordersByUserId.get(userId) ?? [])];
    },
    getOrderById(orderId) {
      return ordersById.get(orderId);
    },
  };
}

export const testUserId = "00000000-0000-0000-0000-000000000000";
export const janeUserId = "00000000-0000-0000-0000-000000000001";

export function createDefaultOrderStore() {
  return createOrderStore([
    { orderId: "order-001", userId: testUserId },
    { orderId: "order-002", userId: testUserId },
    { orderId: "order-003", userId: janeUserId },
    { orderId: "order-004", userId: janeUserId },
  ]);
}
