import sys
import os

def read_file_content(file_path):
    with open(file_path, 'r') as f:
        return f.read()

def generate_pipe_content(json_content, p4info_content):
    # Escape newlines and double quotes in JSON content
    json_content_escaped = json_content.replace('\n', '\\n').replace('"', r'\"')

    # Indent the P4Info content properly
    indented_p4info_content = "\n".join([" " * 4 + line for line in p4info_content.splitlines()])

    # Construct the base content with proper indentation
    pipe_content = f"""
node_id_to_config {{
    key: 1
    value {{
        p4info {{
{indented_p4info_content}
        }}
        p4_device_config: "{json_content_escaped}"
        cookie {{
            cookie: 3710752237043695765
        }}
    }}
}}
"""
    return pipe_content.strip()

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 generatepipe.py <input_json_file> <input_p4info_file>")
        sys.exit(1)

    # Get the input file paths from command-line arguments
    json_file_path = sys.argv[1]
    p4info_file_path = sys.argv[2]

    # Verify the input files exist
    if not os.path.exists(json_file_path):
        print(f"Error: JSON file not found: {json_file_path}")
        sys.exit(1)

    if not os.path.exists(p4info_file_path):
        print(f"Error: P4Info file not found: {p4info_file_path}")
        sys.exit(1)

    # Read the content from the input files
    json_content = read_file_content(json_file_path)
    p4info_content = read_file_content(p4info_file_path)

    # Generate the pipe.txt content
    pipe_content = generate_pipe_content(json_content, p4info_content)

    # Write the generated content to pipe.txt
    with open("pipe.txt", "w") as file:
        file.write(pipe_content)

    print("File 'pipe.txt' has been created with the specified content.")

if __name__ == "__main__":
    main()
