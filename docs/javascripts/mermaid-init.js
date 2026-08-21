const diagrams = [...document.querySelectorAll(".pysec-mermaid > code")];

if (diagrams.length) {
  let started = false;
  const render = async () => {
    if (started) return;
    started = true;
    const { default: mermaid } = await import("mermaid");
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
