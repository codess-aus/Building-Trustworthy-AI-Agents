# Getting Started

<img src="../images/hero-build.svg" alt="Getting Started with AI Agents" style="width: 100%; max-height: 250px; object-fit: cover; border-radius: 8px; margin-bottom: 2em; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);" role="img" aria-label="Getting Started with AI Agents Hero Image">

## Prerequisites

Before you begin building AI agents, ensure you have the following:

- **Azure Subscription**: Access to Azure AI services
- **Development Environment**: Python 3.9+ or .NET 8+
- **API Keys**: For Azure OpenAI or other AI services
- **Basic Knowledge**: Understanding of REST APIs and async programming

## Setting Up Your Development Environment

### 1. Install Required Tools

=== "Python"

    ```bash
    # Create a virtual environment
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate

    # Install core packages
    pip install azure-ai-inference
    pip install azure-identity
    pip install semantic-kernel
    pip install python-dotenv
    ```

=== ".NET"

    ```bash
    # Create a new project
    dotnet new console -n MyAIAgent
    cd MyAIAgent

    # Install NuGet packages
    dotnet add package Azure.AI.Inference
    dotnet add package Azure.Identity
    dotnet add package Microsoft.SemanticKernel
    ```

### 2. Configure Environment Variables

Create a `.env` file in your project root:

```bash
# Azure OpenAI Configuration
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_API_KEY=your-api-key
AZURE_OPENAI_DEPLOYMENT=gpt-4

# Azure AI Search (for RAG)
AZURE_SEARCH_ENDPOINT=https://your-search.search.windows.net
AZURE_SEARCH_KEY=your-search-key
AZURE_SEARCH_INDEX=your-index-name
```

!!! warning "Security Best Practice"
    Never commit API keys to version control. Always use environment variables or Azure Key Vault for sensitive configuration.

## Your First AI Agent

Let's build a simple AI agent using Azure OpenAI and Semantic Kernel.

### Step 1: Initialize the Agent

=== "Python"

    ```python
    import os
    from dotenv import load_dotenv
    from semantic_kernel import Kernel
    from semantic_kernel.connectors.ai.open_ai import AzureChatCompletion
    from semantic_kernel.prompt_template import PromptTemplateConfig

    # Load environment variables
    load_dotenv()

    # Initialize kernel
    kernel = Kernel()

    # Add Azure OpenAI chat service
    kernel.add_service(
        AzureChatCompletion(
            deployment_name=os.getenv("AZURE_OPENAI_DEPLOYMENT"),
            endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
            api_key=os.getenv("AZURE_OPENAI_API_KEY")
        )
    )
    ```

=== ".NET"

    ```csharp
    using Microsoft.SemanticKernel;
    using Azure.AI.OpenAI;
    using Azure.Identity;

    // Initialize kernel
    var builder = Kernel.CreateBuilder();

    builder.AddAzureOpenAIChatCompletion(
        deploymentName: Environment.GetEnvironmentVariable("AZURE_OPENAI_DEPLOYMENT"),
        endpoint: Environment.GetEnvironmentVariable("AZURE_OPENAI_ENDPOINT"),
        apiKey: Environment.GetEnvironmentVariable("AZURE_OPENAI_API_KEY")
    );

    var kernel = builder.Build();
    ```

### Step 2: Create a Simple Function

=== "Python"

    ```python
    from semantic_kernel.functions import kernel_function

    class CustomerServiceAgent:
        @kernel_function(
            name="answer_question",
            description="Answers customer service questions"
        )
        def answer_question(self, question: str) -> str:
            """Process customer questions with context."""
            prompt = f"""
            You are a helpful customer service agent.

            Customer Question: {question}

            Provide a clear, concise, and helpful response.
            """

            result = kernel.invoke_prompt(prompt)
            return str(result)

    # Register the agent
    agent = CustomerServiceAgent()
    kernel.add_plugin(agent, plugin_name="customer_service")
    ```

=== ".NET"

    ```csharp
    public class CustomerServiceAgent
    {
        [KernelFunction("answer_question")]
        [Description("Answers customer service questions")]
        public async Task<string> AnswerQuestion(
            [Description("The customer's question")] string question)
        {
            var prompt = $@"
            You are a helpful customer service agent.

            Customer Question: {question}

            Provide a clear, concise, and helpful response.
            ";

            var result = await kernel.InvokePromptAsync(prompt);
            return result.ToString();
        }
    }

    // Register the agent
    kernel.ImportPluginFromObject(new CustomerServiceAgent());
    ```

### Step 3: Add Safety Guardrails

=== "Python"

    ```python
    from typing import Optional

    class SafetyFilter:
        def __init__(self):
            self.blocked_words = ["inappropriate", "harmful"]

        def validate_input(self, user_input: str) -> tuple[bool, Optional[str]]:
            """Validate user input for safety."""
            # Check for blocked content
            for word in self.blocked_words:
                if word.lower() in user_input.lower():
                    return False, "Input contains inappropriate content"

            # Check input length
            if len(user_input) > 1000:
                return False, "Input exceeds maximum length"

            return True, None

        def validate_output(self, output: str) -> tuple[bool, Optional[str]]:
            """Validate agent output for safety."""
            # Similar validation for output
            if len(output) > 2000:
                return False, "Output exceeds maximum length"

            return True, None

    # Use the safety filter
    safety = SafetyFilter()

    def safe_agent_call(question: str):
        # Validate input
        is_valid, error = safety.validate_input(question)
        if not is_valid:
            return f"Error: {error}"

        # Process with agent
        response = agent.answer_question(question)

        # Validate output
        is_valid, error = safety.validate_output(response)
        if not is_valid:
            return "Error: Unable to generate safe response"

        return response
    ```

=== ".NET"

    ```csharp
    public class SafetyFilter
    {
        private readonly string[] _blockedWords = { "inappropriate", "harmful" };

        public (bool IsValid, string? Error) ValidateInput(string input)
        {
            // Check for blocked content
            foreach (var word in _blockedWords)
            {
                if (input.Contains(word, StringComparison.OrdinalIgnoreCase))
                {
                    return (false, "Input contains inappropriate content");
                }
            }

            // Check input length
            if (input.Length > 1000)
            {
                return (false, "Input exceeds maximum length");
            }

            return (true, null);
        }
    }
    ```

### Step 4: Run Your Agent

=== "Python"

    ```python
    def main():
        print("AI Agent Ready!")

        while True:
            question = input("\nYou: ")
            if question.lower() in ["exit", "quit"]:
                break

            response = safe_agent_call(question)
            print(f"\nAgent: {response}")

    if __name__ == "__main__":
        main()
    ```

=== ".NET"

    ```csharp
    public static async Task Main(string[] args)
    {
        Console.WriteLine("AI Agent Ready!");

        while (true)
        {
            Console.Write("\nYou: ");
            var question = Console.ReadLine();

            if (question?.ToLower() is "exit" or "quit")
                break;

            var response = await SafeAgentCall(question);
            Console.WriteLine($"\nAgent: {response}");
        }
    }
    ```

## Testing Your Agent

!!! tip "Testing Best Practices"
    - Test with diverse inputs
    - Verify safety guardrails
    - Check error handling
    - Monitor performance metrics
    - Test edge cases

### Example Test Cases

```python
def test_agent():
    test_cases = [
        "What are your business hours?",
        "How do I reset my password?",
        "Tell me about your return policy",
        "",  # Empty input
        "x" * 1500,  # Too long
    ]

    for case in test_cases:
        print(f"\nTest: {case[:50]}...")
        response = safe_agent_call(case)
        print(f"Response: {response[:100]}...")
```

## Next Steps

Now that you have a basic agent running:

1. Explore [Best Practices](best-practices.md) for production-ready agents
2. Learn about [Deployment Strategies](deployment.md)
3. Review [Security Considerations](../security/index.md)
4. Understand [Privacy Requirements](../privacy/index.md)

<div class="resource-links">
<h3>📚 Microsoft Learn Resources</h3>
<ul>
<li><a href="https://learn.microsoft.com/en-gb/azure/ai-foundry/agents/overview?view=foundry" target="_blank" rel="noopener">Agent Development Overview</a></li>
<li><a href="https://learn.microsoft.com/en-gb/azure/ai-foundry/quickstarts/get-started-code?view=foundry&tabs=python%2Cpython2" target="_blank" rel="noopener">Microsoft Foundry Quickstart</a></li>
<li><a href="https://learn.microsoft.com/en-gb/azure/ai-foundry/agents/concepts/tool-catalog?view=foundry" target="_blank" rel="noopener">Agent Tools and Integration</a></li>
<li><a href="https://learn.microsoft.com/azure/ai-services/agents/quickstart" target="_blank" rel="noopener">Building Your First Agent</a></li>
</ul>
</ul>
</div>
