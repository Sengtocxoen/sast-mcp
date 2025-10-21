# Contributing to MCP-SAST-Server

Thank you for considering contributing to MCP-SAST-Server! This document provides guidelines and instructions for contributing.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:

1. **Clear title** - Descriptive summary of the issue
2. **Steps to reproduce** - Detailed steps to reproduce the problem
3. **Expected behavior** - What you expected to happen
4. **Actual behavior** - What actually happened
5. **Environment details** - OS, Python version, tool versions
6. **Logs** - Relevant error messages or logs

### Suggesting Enhancements

Feature requests are welcome! Please create an issue with:

1. **Clear description** - What feature you'd like to see
2. **Use case** - Why this feature would be useful
3. **Proposed solution** - If you have ideas on implementation
4. **Alternatives** - Other solutions you've considered

### Pull Requests

1. **Fork the repository**
   ```bash
   git clone https://github.com/your-username/MCP-SAST-Server.git
   cd MCP-SAST-Server
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the existing code style
   - Add comments for complex logic
   - Update documentation if needed

4. **Test your changes**
   - Ensure server starts without errors
   - Test affected SAST tools
   - Verify MCP client integration works

5. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add: description of your changes"
   ```

   Use conventional commit messages:
   - `Add:` for new features
   - `Fix:` for bug fixes
   - `Update:` for improvements
   - `Docs:` for documentation changes
   - `Refactor:` for code refactoring

6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**
   - Go to the original repository
   - Click "New Pull Request"
   - Select your branch
   - Provide a clear description of changes

## Development Setup

### Prerequisites

- Python 3.8+
- Git
- SAST tools for testing (optional)

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/your-username/MCP-SAST-Server.git
cd MCP-SAST-Server

# Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env
# Edit .env with your settings
```

### Running the Server Locally

```bash
# Start the server
python sast_server.py --port 6000 --debug

# In another terminal, test the health endpoint
curl http://localhost:6000/health
```

## Code Style Guidelines

### Python Code Style

- Follow PEP 8 style guide
- Use meaningful variable names
- Add docstrings for functions and classes
- Keep functions focused and concise
- Use type hints where appropriate

Example:
```python
def scan_with_tool(target: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a security scan with the specified tool.

    Args:
        target: Path to the code to scan
        config: Configuration parameters for the scan

    Returns:
        Dictionary containing scan results and metadata
    """
    # Implementation here
    pass
```

### Documentation

- Update README.md for new features
- Add comments for complex logic
- Include usage examples
- Update API documentation if adding endpoints

## Adding New SAST Tools

To add support for a new SAST tool:

1. **Add endpoint in `sast_server.py`**
   ```python
   @app.route("/api/sast/your-tool", methods=["POST"])
   def your_tool():
       """Execute Your Tool scanner"""
       # Implementation
   ```

2. **Add MCP function in `sast_mcp_client.py`**
   ```python
   @mcp.tool()
   def your_tool_scan(
       target: str = ".",
       # other parameters
   ) -> Dict[str, Any]:
       """
       Execute Your Tool for security scanning.

       Args:
           target: Path to code directory

       Returns:
           Scan results
       """
       # Implementation
   ```

3. **Update documentation**
   - Add tool to README.md "Supported Tools" section
   - Add installation instructions
   - Add usage example

4. **Test the integration**
   - Verify endpoint works
   - Test MCP client function
   - Ensure error handling works

## Testing

Currently, this project doesn't have automated tests. Contributions to add testing infrastructure are welcome!

### Manual Testing Checklist

Before submitting a PR, verify:

- [ ] Server starts without errors
- [ ] Health endpoint returns 200 OK
- [ ] New/modified endpoints work correctly
- [ ] MCP client can communicate with server
- [ ] Path resolution works (Windows/Linux)
- [ ] Error handling is appropriate
- [ ] Documentation is updated

## Project Goals

When contributing, keep these goals in mind:

1. **Ease of Use** - Configuration should be simple
2. **Security** - Handle sensitive data appropriately
3. **Reliability** - Graceful error handling
4. **Performance** - Efficient execution of scans
5. **Compatibility** - Cross-platform support
6. **Documentation** - Clear and comprehensive

## Questions?

Feel free to:
- Open an issue for questions
- Start a discussion on GitHub Discussions
- Reach out to maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to MCP-SAST-Server!
