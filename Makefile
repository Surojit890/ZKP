.PHONY: help setup install venv backend frontend test test-xss test-mitm test-replay test-all clean

# Variables
PYTHON := python3
BACKEND_DIR := backend
FRONTEND_DIR := frontend
TESTS_DIR := tests
VENV_DIR := $(BACKEND_DIR)/venv

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m # No Color

# Use this help methd or run the help mthod using the make help to get help
help:
	@echo "$(GREEN)ZKP Project Makefile$(NC)"
	@echo ""
	@echo "$(YELLOW)Setup Targets:$(NC)"
	@echo "  make setup           - Create venv and install dependencies (one-time setup)"
	@echo "  make venv            - Create virtual environment"
	@echo "  make install         - Install dependencies from requirements.txt"
	@echo ""
	@echo "$(YELLOW)Server Targets:$(NC)"
	@echo "  make backend         - Run backend server on port 5000"
	@echo "  make frontend        - Run frontend server on port 8001"
	@echo ""
	@echo "$(YELLOW)Test Targets:$(NC)"
	@echo "  make test-xss        - Run XSS tests"
	@echo "  make test-mitm       - Run MITM tests"
	@echo "  make test-replay     - Run replay attack tests"
	@echo "  make test-all        - Run all tests sequentially"
	@echo ""
	@echo "$(YELLOW)Cleanup:$(NC)"
	@echo "  make clean           - Remove virtual environment and __pycache__"

# One-time setup
setup: venv install
	@echo "$(GREEN)Setup complete! You can now run 'make backend' and 'make frontend' in separate terminals.$(NC)"

# Create virtual environment
venv:
	@echo "$(YELLOW)Creating virtual environment...$(NC)"
	@cd $(BACKEND_DIR) && $(PYTHON) -m venv venv
	@echo "$(GREEN)Virtual environment created at $(VENV_DIR)$(NC)"

# Install dependencies
install:
	@echo "$(YELLOW)Installing dependencies...$(NC)"
	@. $(VENV_DIR)/bin/activate && pip install -r $(BACKEND_DIR)/requirements.txt
	@echo "$(GREEN)Dependencies installed successfully$(NC)"

# Backend server
backend:
	@echo "$(YELLOW)Starting backend server on http://127.0.0.1:5000$(NC)"
	@. $(VENV_DIR)/bin/activate && cd $(BACKEND_DIR) && python app_final.py

# Frontend server
frontend:
	@echo "$(YELLOW)Starting frontend server on http://localhost:8001$(NC)"
	@cd $(FRONTEND_DIR) && $(PYTHON) -m http.server 8001

# XSS Tests
test-xss:
	@echo "$(YELLOW)Running XSS tests...$(NC)"
	@. $(VENV_DIR)/bin/activate && python $(TESTS_DIR)/test_xss_vectors.py

# MITM Tests
test-mitm:
	@echo "$(YELLOW)Running MITM tests...$(NC)"
	@. $(VENV_DIR)/bin/activate && python $(TESTS_DIR)/test_mitm_vectors.py

# Replay Attack Tests
test-replay:
	@echo "$(YELLOW)Running replay attack tests...$(NC)"
	@. $(VENV_DIR)/bin/activate && python $(TESTS_DIR)/test_replay_attacks.py

# All tests
test-all: test-xss test-mitm test-replay
	@echo "$(GREEN)All security tests completed!$(NC)"

# Clean up
clean:
	@echo "$(YELLOW)Cleaning up...$(NC)"
	@rm -rf $(VENV_DIR)
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete
	@echo "$(GREEN)Cleanup complete$(NC)"
