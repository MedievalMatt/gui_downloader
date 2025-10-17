import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os
import sys

# Ensure the directory of the main script is on the path for import
sys.path.append(os.path.dirname(os.path.abspath(__file__))) 
try:
    # Import the refactored function from the main script
    from archive_org_downloader import run_downloader
except ImportError:
    # This error handling is crucial for the user if the main script isn't found
    try:
        root = tk.Tk()
        root.withdraw() # Hide the root window
        messagebox.showerror("Import Error", "Could not import 'run_downloader' from archive_org-downloader.py. Ensure both files are in the same directory.")
    except:
        print("FATAL ERROR: Could not find archive_org-downloader.py.")
    sys.exit(1)


class DownloaderGUI:
    def __init__(self, master):
        self.master = master
        master.title("Archive.org Downloader GUI")
        
        # Variables
        self.email_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.dir_var = tk.StringVar(value=os.getcwd())
        self.url_var = tk.StringVar()
        self.file_var = tk.StringVar()
        self.meta_var = tk.BooleanVar()
        self.jpg_var = tk.BooleanVar()
        self.res_var = tk.IntVar(value=3)
        self.thread_var = tk.IntVar(value=50)

        # Setup Layout
        self.master.columnconfigure(0, weight=1)
        self.master.columnconfigure(1, weight=0)
        row_idx = 0

        # UI Widgets (Grid layout for organization)
        tk.Label(master, text="Email:").grid(row=row_idx, column=0, columnspan=2, padx=5, pady=(5,0), sticky="w"); row_idx += 1
        tk.Entry(master, textvariable=self.email_var, width=50).grid(row=row_idx, column=0, columnspan=2, padx=5, pady=(0,5), sticky="we"); row_idx += 1
        
        tk.Label(master, text="Password:").grid(row=row_idx, column=0, columnspan=2, padx=5, pady=(5,0), sticky="w"); row_idx += 1
        tk.Entry(master, textvariable=self.password_var, show="*", width=50).grid(row=row_idx, column=0, columnspan=2, padx=5, pady=(0,5), sticky="we"); row_idx += 1

        tk.Label(master, text="Output Directory (-d):").grid(row=row_idx, column=0, columnspan=2, padx=5, pady=(5,0), sticky="w"); row_idx += 1
        tk.Entry(master, textvariable=self.dir_var, width=40).grid(row=row_idx, column=0, padx=5, pady=(0,5), sticky="we")
        tk.Button(master, text="Browse...", command=self.select_output_dir).grid(row=row_idx, column=1, padx=5, pady=(0,5), sticky="w"); row_idx += 1

        tk.Label(master, text="Book URL(s) (separate multiple with space):").grid(row=row_idx, column=0, columnspan=2, padx=5, pady=(5,0), sticky="w"); row_idx += 1
        tk.Entry(master, textvariable=self.url_var, width=50).grid(row=row_idx, column=0, columnspan=2, padx=5, pady=(0,5), sticky="we"); row_idx += 1

        tk.Label(master, text="OR URL File List (-f):").grid(row=row_idx, column=0, padx=5, pady=(5,0), sticky="w"); row_idx += 1
        tk.Entry(master, textvariable=self.file_var, width=40).grid(row=row_idx, column=0, padx=5, pady=(0,5), sticky="we")
        tk.Button(master, text="Browse File...", command=self.select_url_file).grid(row=row_idx, column=1, padx=5, pady=(0,5), sticky="w"); row_idx += 1
        
        # Options Frame
        options_frame = tk.Frame(master)
        options_frame.grid(row=row_idx, column=0, columnspan=2, padx=5, pady=10, sticky="we"); row_idx += 1
        options_frame.columnconfigure(0, weight=1)
        options_frame.columnconfigure(1, weight=1)

        # Left Column Options
        tk.Label(options_frame, text="Resolution (-r, 0=Best):").grid(row=0, column=0, padx=5, sticky="w")
        tk.Spinbox(options_frame, from_=0, to=10, textvariable=self.res_var, width=5).grid(row=0, column=1, padx=5, sticky="w")
        tk.Label(options_frame, text="Threads (-t, default 50):").grid(row=1, column=0, padx=5, sticky="w")
        tk.Spinbox(options_frame, from_=1, to=100, textvariable=self.thread_var, width=5).grid(row=1, column=1, padx=5, sticky="w")
        
        # Right Column Options (Checkboxes)
        tk.Checkbutton(options_frame, text="Output Metadata (-m)", variable=self.meta_var).grid(row=0, column=2, columnspan=2, padx=5, sticky="w")
        tk.Checkbutton(options_frame, text="Output JPGs instead of PDF (-j)", variable=self.jpg_var).grid(row=1, column=2, columnspan=2, padx=5, sticky="w")
        
        # Download Button
        self.download_button = tk.Button(master, text="Start Download", command=self.start_download_thread, bg="#4CAF50", fg="white", height=2)
        self.download_button.grid(row=row_idx, column=0, columnspan=2, padx=10, pady=10, sticky="we"); row_idx += 1
        
        # Status Label
        self.status_label = tk.Label(master, text="Ready", fg="blue", relief=tk.SUNKEN, anchor="w")
        self.status_label.grid(row=row_idx, column=0, columnspan=2, padx=5, pady=(0,5), sticky="we")
        
    def select_output_dir(self):
        directory = filedialog.askdirectory(initialdir=self.dir_var.get())
        if directory:
            self.dir_var.set(directory)

    def select_url_file(self):
        file_path = filedialog.askopenfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.file_var.set(file_path)

    def start_download_thread(self):
        """Validates inputs and starts the download process in a separate thread."""
        email = self.email_var.get().strip()
        password = self.password_var.get().strip()
        directory = self.dir_var.get().strip()
        url_input = self.url_var.get().strip()
        file_input = self.file_var.get().strip()

        if not email or not password:
            messagebox.showerror("Input Error", "Email and Password are required.")
            return
        if not url_input and not file_input:
            messagebox.showerror("Input Error", "Please provide a Book URL(s) or a URL File List.")
            return
        
        urls = url_input.split() if url_input else None
        
        self.download_button.config(state=tk.DISABLED, text="Downloading... (Check console for progress)")
        self.status_label.config(text="Starting download in background...", fg="orange")
        
        # Pass all collected GUI variables to the run_downloader function
        t = threading.Thread(target=self.download_worker, args=(
            email, 
            password, 
            urls, 
            file_input if file_input else None, 
            directory,
            self.res_var.get(),
            self.thread_var.get(),
            self.jpg_var.get(),
            self.meta_var.get()
        ))
        t.start()

    def download_worker(self, email, password, urls, file_input, directory, resolution, threads, is_jpg, is_meta):
        """The actual download function that runs in a separate thread."""
        success = False
        try:
            success = run_downloader(email, password, urls, file_input, directory, resolution, threads, is_jpg, is_meta)

            if success:
                self.master.after(0, lambda: self.status_label.config(text="Download Complete! 🎉", fg="green"))
                self.master.after(0, lambda: messagebox.showinfo("Success", "Download process finished successfully!"))
            else:
                self.master.after(0, lambda: self.status_label.config(text="Download Failed! 😥 Check console for details.", fg="red"))
                self.master.after(0, lambda: messagebox.showerror("Error", "Download failed. See terminal output for details."))

        except Exception as e:
            self.master.after(0, lambda: self.status_label.config(text=f"Critical Error: {e}", fg="red"))
            self.master.after(0, lambda: messagebox.showerror("Critical Error", f"A critical error occurred: {e}"))
        finally:
            self.master.after(0, lambda: self.download_button.config(state=tk.NORMAL, text="Start Download"))


if __name__ == '__main__':
    root = tk.Tk()
    app = DownloaderGUI(root)
    root.mainloop()
