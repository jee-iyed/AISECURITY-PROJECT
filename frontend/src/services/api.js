const BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
export async function api(path, token, body) {
  const response = await fetch(BASE + path, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const data = await response.json();
  if (!response.ok)
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : "Request failed validation",
    );
  return data;
}
