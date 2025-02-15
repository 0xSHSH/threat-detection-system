# Contributing to Advanced Network Threat Detection System

First off, thank you for considering contributing to our project! It's people like you that make this system better for everyone.

## Code of Conduct

By participating in this project, you are expected to uphold our Code of Conduct:
- Be respectful and inclusive
- Focus on constructive feedback
- Maintain professional discourse

## How Can I Contribute?

### Reporting Bugs

1. **Check Existing Issues** - Search through existing issues to avoid duplicates
2. **Use the Bug Report Template**:
   ```
   **Description**
   [Clear description of the bug]

   **To Reproduce**
   1. [First Step]
   2. [Second Step]
   3. [and so on...]

   **Expected behavior**
   [What you expected to happen]

   **Actual behavior**
   [What actually happened]

   **System Information**
   - OS: [e.g., Windows 10]
   - Python Version: [e.g., 3.8.5]
   - Package Versions: [relevant package versions]
   ```

### Suggesting Enhancements

1. **Use the Feature Request Template**:
   ```
   **Problem**
   [Description of the problem this feature would solve]

   **Proposed Solution**
   [Your idea for implementing the feature]

   **Alternatives Considered**
   [Other solutions you've considered]

   **Additional Context**
   [Any other relevant information]
   ```

### Pull Requests

1. **Fork the Repository**
2. **Create a Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make Your Changes**:
   - Follow the coding style
   - Add tests for new features
   - Update documentation
4. **Commit Your Changes**:
   ```bash
   git commit -m "Add: brief description of changes"
   ```
5. **Push to Your Fork**:
   ```bash
   git push origin feature/your-feature-name
   ```
6. **Submit a Pull Request**

## Development Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/threat-detection-system.git
   cd threat-detection-system
   ```

2. **Create Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   .\venv\Scripts\activate   # Windows
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run Tests**:
   ```bash
   python -m pytest
   ```

## Coding Guidelines

1. **Code Style**:
   - Follow PEP 8
   - Use meaningful variable names
   - Add docstrings to functions and classes

2. **Testing**:
   - Write unit tests for new features
   - Maintain test coverage above 80%
   - Test edge cases

3. **Documentation**:
   - Update README.md if needed
   - Add inline comments for complex logic
   - Update API documentation

## Git Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit first line to 72 characters
- Reference issues and pull requests after first line

Examples:
```
Add feature detection for DNS tunneling
Fix: memory leak in packet processing
Update: documentation for DBSCAN parameters
```

## Questions?

Feel free to:
1. Open an issue for discussion
2. Contact maintainers
3. Join our community chat

Thank you for contributing!
