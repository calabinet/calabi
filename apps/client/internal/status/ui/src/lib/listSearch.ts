export function matchesListSearch(query: string, ...values: (string | number | null | undefined)[]): boolean {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const text = values.filter(value => value != null).join(" ").toLowerCase();
  return terms.every(term => text.includes(term));
}
