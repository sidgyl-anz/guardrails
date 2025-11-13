# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download the spaCy model required by the guardrails
RUN python -m spacy download en_core_web_sm

# Copy the rest of the application code into the container
COPY . .


# Set environment variables for the application
ENV PORT=8080

# Command to run the FastAPI application when the container starts
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
