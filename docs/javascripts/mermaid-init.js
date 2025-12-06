// Initialize Mermaid diagrams
document.addEventListener('DOMContentLoaded', function() {
  if (typeof mermaid !== 'undefined') {
    mermaid.initialize({ 
      startOnLoad: true,
      theme: 'dark',
      themeVariables: {
        primaryColor: '#0d9488',
        primaryTextColor: '#fff',
        primaryBorderColor: '#1e3a8a',
        lineColor: '#0d9488',
        secondaryColor: '#1e3a8a',
        tertiaryColor: '#0ea5e9'
      }
    });
  }
});
