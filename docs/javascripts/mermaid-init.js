const diagrams = [...document.querySelectorAll(".pysec-mermaid > code")];
const mermaidSource = "https://unpkg.com/mermaid@11.12.0/dist/mermaid.min.js";
const mermaidIntegrity =
  "sha384-o+g/BxPwhi0C3RK7oQBxQuNimeafQ3GE/ST4iT2BxVI4Wzt60SH4pq9iXVYujjaS"; // pragma: allowlist secret

if (diagrams.length) {
  let started = false;
  const loadMermaid = () =>
    new Promise((resolve, reject) => {
      if (window.mermaid) {
        resolve(window.mermaid);
        return;
      }
      const script = document.createElement("script");
      script.src = mermaidSource;
      script.integrity = mermaidIntegrity;
      script.crossOrigin = "anonymous";
      script.referrerPolicy = "no-referrer";
      script.addEventListener("load", () => resolve(window.mermaid), { once: true });
      script.addEventListener(
        "error",
        () => reject(new Error("The integrity-checked Mermaid bundle failed to load")),
        { once: true },
      );
      document.head.append(script);
    });
  const render = async () => {
    if (started) return;
    started = true;
    const mermaid = await loadMermaid();
    if (!mermaid) throw new Error("The Mermaid bundle did not expose its API");
    mermaid.initialize({ startOnLoad: false });
    await mermaid.run({ nodes: diagrams });
  };
  const start = () => {
    void render().catch((error) => {
      document.documentElement.dataset.mermaidError = JSON.stringify(
        error,
        Object.getOwnPropertyNames(error),
      );
    });
  };

  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          observer.disconnect();
          start();
        }
      },
      { rootMargin: "200px" },
    );
    for (const diagram of diagrams) observer.observe(diagram);
  } else {
    start();
  }
}
