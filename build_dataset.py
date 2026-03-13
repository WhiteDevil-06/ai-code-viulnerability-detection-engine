import os
import re
import random
import pandas as pd

# Define the dataset directories we created
BASE_DIR = "dataset"
CATEGORIES = {
    "safe": 0,
    "sql_injection": 1,
    "command_injection": 2,
    "unsafe_eval": 3,
    "xss": 4
}

def clean_code(code_string):
    """
    Module 2: Code Preprocessing
    Removes comments, docstrings, and normalizes spacing.
    """
    # Remove single line comments
    code_string = re.sub(r'#.*', '', code_string)
    # Remove multi-line strings / docstrings
    code_string = re.sub(r'\"\"\"[\s\S]*?\"\"\"', '', code_string)
    code_string = re.sub(r"\'\'\'[\s\S]*?\'\'\'", '', code_string)
    # Remove blank lines and extra whitespace
    lines = [line.strip() for line in code_string.split('\n') if line.strip()]
    return ' '.join(lines)  # Tokenize by flattening into a single string for TF-IDF

def generate_synthetic_sard_samples(num_samples_per_class=100):
    """
    To jumpstart our training efficiently without a massive download, 
    we generate highly representative SARD/Juliet style payloads 
    for our 4 vulnerability classes, and clean Safe code examples.
    """
    print(f"[*] Generating {num_samples_per_class} baseline samples per category...")
    
    # 0. Safe Code Patterns
    safe_templates = [
        "def get_user(user_id):\n    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n    return cursor.fetchone()",
        "def safe_eval(math_string):\n    import ast\n    return ast.literal_eval(math_string)",
        "def ping_host(host):\n    import subprocess\n    subprocess.run(['ping', '-c', '1', host])",
        "from flask import escape\ndef render_name(name):\n    return f'Hello {escape(name)}'"
    ]
    
    # 1. SQL Injection (CWE-89)
    sql_templates = [
        "def get_user(user_id):\n    query = f'SELECT * FROM users WHERE id = {user_id}'\n    cursor.execute(query)",
        "def login(username, password):\n    cursor.execute('SELECT * FROM users WHERE user=\"' + username + '\" AND pass=\"' + password + '\"')",
        "def search(query):\n    return db.execute('SELECT * FROM items WHERE name LIKE %s' % query)"
    ]
    
    # 2. Command Injection (CWE-78)
    cmd_templates = [
        "def ping_host(host):\n    import os\n    os.system('ping -c 1 ' + host)",
        "def run_script(script_name):\n    import subprocess\n    subprocess.Popen(f'sh {script_name}', shell=True)",
        "def backup(dir_name):\n    import os\n    os.system(f'tar -czvf backup.tar.gz {dir_name}')"
    ]
    
    # 3. Unsafe Eval
    eval_templates = [
        "def calculate(math_string):\n    return eval(math_string)",
        "def execute_dynamic(code_string):\n    exec(code_string)",
        "def load_yaml(data):\n    import yaml\n    return yaml.load(data, Loader=yaml.Loader)"
    ]
    
    # 4. XSS (CWE-79)
    xss_templates = [
        "def render_page(user_input):\n    return f'<html><body>Hello {user_input}</body></html>'",
        "from flask import request\n@app.route('/greet')\ndef greet():\n    name = request.args.get('name')\n    return '<h1>Welcome ' + name + '</h1>'",
        "def generate_div(content):\n    return '<div>' + content + '</div>'"
    ]
    
    templates = {
        "safe": safe_templates,
        "sql_injection": sql_templates,
        "command_injection": cmd_templates,
        "unsafe_eval": eval_templates,
        "xss": xss_templates
    }
    
    # Create the files in the respective directories
    for category, tmpl_list in templates.items():
        cat_dir = os.path.join(BASE_DIR, category)
        os.makedirs(cat_dir, exist_ok=True)
        for i in range(num_samples_per_class):
            # Select a random template and add slight random variations
            code = random.choice(tmpl_list)
            var_suffix = random.randint(100, 999)
            code = code.replace("user_id", f"user_id_{var_suffix}")
            code = code.replace("user_input", f"user_input_{var_suffix}")
            code = code.replace("math_string", f"math_string_{var_suffix}")
            
            file_path = os.path.join(cat_dir, f"sample_{i}.py")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(code)

def build_csv():
    """Reads all generated files, preprocesses them, and saves to CSV."""
    print("[*] Preprocessing raw files and building unified CSV dataset...")
    data = []
    
    for category, class_label in CATEGORIES.items():
        cat_dir = os.path.join(BASE_DIR, category)
        if not os.path.exists(cat_dir):
            continue
            
        for filename in os.listdir(cat_dir):
            if filename.endswith(".py") or filename.endswith(".txt"):
                file_path = os.path.join(cat_dir, filename)
                with open(file_path, 'r', encoding='utf-8') as f:
                    raw_code = f.read()
                    
                cleaned_code = clean_code(raw_code)
                data.append({
                    "code_snippet": cleaned_code,
                    "label": class_label,
                    "category_name": category
                })
                
    df = pd.DataFrame(data)
    csv_path = "dataset.csv"
    df.to_csv(csv_path, index=False)
    print(f"[+] Successfully created {csv_path} with {len(df)} records.")
    print("\nClass Distribution:")
    print(df['category_name'].value_counts())

if __name__ == "__main__":
    generate_synthetic_sard_samples(num_samples_per_class=150)
    build_csv()
