import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox


def calculate_file_hash(file_path, algorithm):
    """
    Calculate the hash of a file using the specified hashing algorithm.
    """
    try:
        hash_func = hashlib.new(algorithm)
        with open(file_path, "rb") as file:
            while chunk := file.read(8192):  # Read the file in chunks
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except FileNotFoundError:
        messagebox.showerror("Error", f"The file '{file_path}' does not exist.")
        return None
    except ValueError:
        messagebox.showerror("Error", f"Unsupported hashing algorithm '{algorithm}'.")
        return None


def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)


def verify_file_integrity():
    file_path = file_entry.get()
    algorithm = algorithm_var.get()
    expected_hash = expected_hash_entry.get().strip()

    if not file_path or not algorithm:
        messagebox.showerror("Error", "Please select a file and hashing algorithm.")
        return

    file_hash = calculate_file_hash(file_path, algorithm)
    if file_hash:
        # Display the hash in the result label
        result_text.set(f"Calculated {algorithm.upper()} Hash:\n{file_hash}")
        
        # If an expected hash is provided, verify it
        if expected_hash:
            if file_hash == expected_hash:
                messagebox.showinfo("Verification Result", "✅ File integrity is intact!")
            else:
                messagebox.showwarning("Verification Result", "❌ File integrity is compromised!")


def calculate_hash_only():
    """
    Calculate and display the file hash without verifying it against an expected value.
    """
    file_path = file_entry.get()
    algorithm = algorithm_var.get()

    if not file_path or not algorithm:
        messagebox.showerror("Error", "Please select a file and hashing algorithm.")
        return

    file_hash = calculate_file_hash(file_path, algorithm)
    if file_hash:
        result_text.set(f"Calculated {algorithm.upper()} Hash:\n{file_hash}")


def copy_to_clipboard():
    """
    Copy the calculated hash to the clipboard.
    """
    hash_value = result_text.get().split("Hash:\n")[-1].strip()  # Extract the hash value
    if hash_value:
        root.clipboard_clear()
        root.clipboard_append(hash_value)
        root.update()  # Update the clipboard
        messagebox.showinfo("Copied", "Hash value copied to clipboard!")
    else:
        messagebox.showerror("Error", "No hash value to copy.")


# Initialize the main window
root = tk.Tk()
root.title("Secure File Integrity Checker")
root.geometry("500x400")
root.resizable(True, True)

# File selection
file_label = tk.Label(root, text="Select File:")
file_label.pack(pady=5)
file_entry = tk.Entry(root, width=50)
file_entry.pack(pady=5, fill="x", padx=10)
file_button = tk.Button(root, text="Browse", command=select_file)
file_button.pack(pady=5)

# Hashing algorithm selection
algorithm_label = tk.Label(root, text="Choose Hashing Algorithm:")
algorithm_label.pack(pady=5)
algorithm_var = tk.StringVar(value="md5")
algorithm_dropdown = tk.OptionMenu(root, algorithm_var, "md5", "sha1", "sha256")
algorithm_dropdown.pack(pady=5)

# Expected hash input
expected_hash_label = tk.Label(root, text="Expected Hash (optional):")
expected_hash_label.pack(pady=5)
expected_hash_entry = tk.Entry(root, width=50)
expected_hash_entry.pack(pady=5, fill="x", padx=10)

# Buttons for functionality
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

verify_button = tk.Button(button_frame, text="Verify Integrity", command=verify_file_integrity)
verify_button.grid(row=0, column=0, padx=10)

calculate_button = tk.Button(button_frame, text="Calculate Hash Only", command=calculate_hash_only)
calculate_button.grid(row=0, column=1, padx=10)

copy_button = tk.Button(button_frame, text="Copy Hash", command=copy_to_clipboard)
copy_button.grid(row=0, column=2, padx=10)

# Result display
result_text = tk.StringVar()
result_label = tk.Label(root, textvariable=result_text, fg="blue", wraplength=480, justify="left")
result_label.pack(pady=10, fill="x", padx=10)

# Run the main loop
root.mainloop()
