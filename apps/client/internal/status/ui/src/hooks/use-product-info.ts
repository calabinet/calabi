import { useQuery } from "@tanstack/react-query";

type ProductInfo = { product: "desktop"; version: string; bundled_core_version: string; bundled_core_commit: string };
type NativeWindow = Window & { __TAURI_INTERNALS__?: { invoke<T>(command: string): Promise<T> } };

export function useProductInfo() {
  const bridge = (window as NativeWindow).__TAURI_INTERNALS__;
  const query = useQuery({
    queryKey: ["product-info"],
    queryFn: () => bridge!.invoke<ProductInfo>("product_info"),
    enabled: !!bridge,
    refetchInterval: 30_000,
    retry: false,
  });
  return { desktop: !!bridge, info: query.data };
}
