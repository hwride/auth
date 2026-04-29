export type ProductRecord = {
  productId: string;
  name: string;
};

export type ProductStore = {
  getProductsAll(): ProductRecord[];
  getProductById(productId: string): ProductRecord | undefined;
};

export function createProductStore(
  initialProducts: ProductRecord[] = [],
): ProductStore {
  const productsById = new Map(
    initialProducts.map(function (product) {
      return [product.productId, product];
    }),
  );

  return {
    getProductsAll() {
      return [...productsById.values()];
    },
    getProductById(productId) {
      return productsById.get(productId);
    },
  };
}

export function createDefaultProductStore() {
  return createProductStore([
    { productId: "product-001", name: "Keyboard" },
    { productId: "product-002", name: "Mouse" },
  ]);
}
