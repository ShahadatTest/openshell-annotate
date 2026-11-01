// @openshell egress api.openai.com:443 reason="LLM calls" access=read-write
// @openshell provider OPENAI_API_KEY
export async function chat(body: unknown) {
  const url = "https://api.openai.com/v1/chat/completions";
  const note = "// @openshell egress not-a-directive.test:443 reason=\"inside a string\"";
  return fetch(url, { method: "POST", headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` }, body: JSON.stringify(body) });
}
