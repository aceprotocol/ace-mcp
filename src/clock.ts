/** Unix time in whole seconds: the clock of every stored timestamp. */
export const nowSeconds = (): number => Math.floor(Date.now() / 1000);
