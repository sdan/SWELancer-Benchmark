# Get your agent to work 50X faster by running SWE-Lancer on Morph Cloud

<p align="center">
  <img src="./images/swelancer-splash.png" alt="Morph Cloud Integration" width="100%" style="max-width: 100%; height: auto;" />
</p>

## Accelerated Evaluation with Morph Cloud

This fork enhances SWELancer with Morph Cloud integration to significantly reduce the time to first agent action (up to 50x faster) when running evaluations. Morph Cloud's snapshotting capabilities allow agents to drop directly into the exact task state needed, bypassing the lengthy setup process for tasks you've run before.

[Apply for early access here](https://docs.google.com/forms/d/1F8JeJEJWwP5ywfmGN_N-r3MBNHVzry7k1Dg_2YEex28)

### Key Benefits
- Reduces setup time from ~550 seconds to ~10 seconds for IC SWE tasks
- Reduces setup time from ~30 seconds to ~10 seconds for Manager tasks
- Drastically improves iteration cycles for researchers and developers
- Handles Docker build for you

### Getting Started with Morph Cloud

To use Morph Cloud's accelerated evaluation:

```bash
# Complete basic setup (skip Docker build step)
uv sync
source .venv/bin/activate
for proj in nanoeval alcatraz nanoeval_alcatraz; do
  uv pip install -e project/"$proj"
done

# Install Morph Cloud and set API key
uv pip install morphcloud
export MORPH_API_KEY=your_api_key_here

# Run with Morph Cloud enabled
uv run python run_swelancer.py --use_morph
```

### How It Works

The Morph Cloud integration:
1. Creates a VM to build the Docker image, and run the container setup for a given issue
1. Automatically creates snapshots of the container on each initial issue run
3. Reuses these snapshots in subsequent runs to bypass setup time
4. Maintains full compatibility with the original evaluation framework

### Contact Us
Pre-built snapshots are available to select early users of [Morph Cloud](https://cloud.morph.so/developers) — [apply for early access](https://docs.google.com/forms/d/1F8JeJEJWwP5ywfmGN_N-r3MBNHVzry7k1Dg_2YEex28) to learn more.

## SWE-Lancer

This repo contains the dataset and code for the paper ["SWE-Lancer: Can Frontier LLMs Earn $1 Million from Real-World Freelance Software Engineering?"](https://www.openai.com/index/swe-lancer/).

---

Thank you so much for checking out our benchmark! If you have questions, run into issues, or want to contribute, please open an issue or pull request. You can also reach us at samuelgm@openai.com and michele@openai.com at any time.

We will continue to update this repository with the latest tasks, updates to the scaffolding, and improvements to the codebase 

- If you'd like to use the latest version, please use the `main` branch.

- If you'd like to use the version of the dataset from the paper and codebase at time of paper release, please check out the `paper` branch. Note that the performance outlined in our paper is on our internal scaffold. We've aimed to open-source as much of it as possible, but the open-source agent and harness may not be exactly the same. 


---

**Step 1: Package Management and Requirements**

Python 3.11 is the most stable version to use with SWE-Lancer.

For package management, this repo comes with a pre-existing virtualenv or you can build one from scratch.

We recommend using the pre-built virtualenv with [uv](https://github.com/astral-sh/uv), a lightweight OSS package manager. To do this, run:

```bash
uv sync
source .venv/bin/activate
for proj in nanoeval alcatraz nanoeval_alcatraz; do
  uv pip install -e project/"$proj"
done
```

To use your own virtualenv, without uv, run:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
for proj in nanoeval alcatraz nanoeval_alcatraz; do
  pip install -e project/"$proj"
done
```

**Step 2: Build the Docker Image**

Please run the command that corresponds to your computer's architecture.

For Apple Silicon (or other ARM64 systems):

```bash
docker buildx build \
  -f Dockerfile \
  --ssh default=$SSH_AUTH_SOCK \
  -t swelancer \
  .
```

For Intel-based Mac (or other x86_64 systems):

```bash
docker buildx build \
  -f Dockerfile_x86 \
  --platform linux/amd64 \
  --ssh default=$SSH_AUTH_SOCK \
  -t swelancer \
  .
```

After the command completes, run the Docker container.

**Step 3: Configure Environment Variables**

Ensure you have an OpenAI API key and username set on your machine.

Locate the `sample.env` file in the root directory. This file contains template environment variables needed for the application:

```plaintext
# sample.env contents example:
PUSHER_APP_ID=your-app-id
# ... other variables
```

Create a new file named `.env` and copy the contents from `sample.env`.

**Step 4: Running SWE-Lancer**

You are now ready to run the eval with:

```bash
uv run python run_swelancer.py
```

You should immediately see logging output as the container gets set up and the tasks are loaded, which may take several minutes. You can adjust the model, concurrency, recording, and other parameters in `run_swelancer.py`.

## Running at Scale

To run SWELancer at scale in your own environment, you'll need to implement your own compute infrastructure. Here's a high-level overview of how to integrate SWELancer with your compute system:

### 1. Implement a Custom ComputerInterface

Create your own implementation of the `ComputerInterface` class that interfaces with your compute infrastructure. The main methods you need to implement are:

```python
class YourComputerInterface(ComputerInterface):
  async def send_shell_command(self, command: str) -> CommandResult:
    """Execute a shell command and return the result"""
    pass
  async def upload(self, local_path: str, remote_path: str) -> None:
    """Upload a file to the compute environment"""
    pass
  async def download(self, remote_path: str) -> bytes:
    """Download a file from the compute environment"""
    pass
  async def check_shell_command(self, command: str) -> CommandResult:
    """Execute a shell command and raise an error if it fails"""
    pass
    async def cleanup(self) -> None:
    """Clean up any resources"""
    pass
```

### 2. Update the Computer Start Function

Modify `swelancer_agent.py`'s `_start_computer` function to use your custom interface:

```python
async def _start_computer(self, task: ComputerTask) -> AsyncGenerator[ComputerInterface, None]:
    # Implement your compute logic here

    # Initialize your compute environment
    # This could involve:
    # - Spinning up a container/VM
    # - Setting up SSH connections
    # - Configuring environment variables
    # Return your custom ComputerInterface implementation
    return YourComputerInterface()
```

### Reference Implementation

For a complete example of a ComputerInterface implementation, you can refer to the `alcatraz_computer_interface.py` file in the codebase. This shows how to:

- Handle command execution
- Manage file transfers
- Deal with environment setup
- Handle cleanup and resource management

### Best Practices

1. **Resource Management**

   - Implement proper cleanup in your interface
   - Handle container/VM lifecycle appropriately
   - Clean up temporary files

2. **Security**

   - Implement proper isolation between tasks
   - Handle sensitive data appropriately
   - Control network access

3. **Scalability**

   - Consider implementing a pool of compute resources
   - Handle concurrent task execution
   - Implement proper resource limits

4. **Error Handling**
   - Implement robust error handling
   - Provide meaningful error messages
   - Handle network issues gracefully

## Citation
```
@misc{miserendino2025swelancerfrontierllmsearn,
      title={SWE-Lancer: Can Frontier LLMs Earn $1 Million from Real-World Freelance Software Engineering?}, 
      author={Samuel Miserendino and Michele Wang and Tejal Patwardhan and Johannes Heidecke},
      year={2025},
      eprint={2502.12115},
      archivePrefix={arXiv},
      primaryClass={cs.LG},
      url={https://arxiv.org/abs/2502.12115}, 
}
```