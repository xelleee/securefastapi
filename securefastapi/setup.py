from setuptools import setup, find_packages

setup(
    name="securefastapi",
    version="1.0.0",
    description="securisation des microservices",
    author="experio",
    packages=find_packages(include=["sdk", "sdk.*"]),
    install_requires=[
        "fastapi",
        "uvicorn",
        "httpx",
        "PyJWT",
        "pydantic"
    ],
    python_requires=">=3.10",
)
