import tkinter as tk
from tkinter import ttk, messagebox
import requests
import json


SERVER_URL = "https://xyron-api-1.onrender.com"

BG = "#030208"
PANEL = "#0b0712"
WHITE = "#f7f2ff"
MUTED = "#81798e"
PURPLE = "#8b4dff"
GREEN = "#63dc9a"
RED = "#ef7777"


class AdminPanel:

    def __init__(self, root):

        self.root = root
        self.token = None

        root.title(
            "XYRON ADMIN"
        )

        root.geometry(
            "900x600"
        )

        root.configure(
            bg=BG
        )

        self.login_ui()


    def clear(self):

        for widget in self.root.winfo_children():
            widget.destroy()


    def login_ui(self):

        self.clear()

        frame = tk.Frame(
            self.root,
            bg=BG
        )

        frame.pack(
            expand=True
        )

        tk.Label(
            frame,
            text="XYRON",
            bg=BG,
            fg=WHITE,
            font=("Arial", 38, "bold")
        ).pack()

        tk.Label(
            frame,
            text="ADMIN PANEL",
            bg=BG,
            fg=PURPLE,
            font=("Arial", 10, "bold")
        ).pack()

        self.admin_key = tk.Entry(
            frame,
            width=35,
            show="*",
            bg=PANEL,
            fg=WHITE,
            insertbackground=WHITE,
            relief="flat",
            justify="center"
        )

        self.admin_key.pack(
            pady=25,
            ipady=9
        )

        tk.Button(
            frame,
            text="LOGIN",
            command=self.login,
            bg=PURPLE,
            fg="white",
            relief="flat",
            bd=0,
            padx=35,
            pady=9
        ).pack()


    def login(self):

        key = self.admin_key.get().strip()

        try:

            response = requests.post(
                SERVER_URL + "/admin/login",
                json={
                    "admin_key": key
                },
                timeout=10
            )

            if response.status_code != 200:

                messagebox.showerror(
                    "Xyron",
                    "Invalid admin key."
                )

                return

            self.token = response.json()["token"]

            self.dashboard()

        except Exception:

            messagebox.showerror(
                "Xyron",
                "Cannot connect to server."
            )


    def dashboard(self):

        self.clear()

        top = tk.Frame(
            self.root,
            bg=BG
        )

        top.pack(
            fill="x",
            padx=25,
            pady=20
        )

        tk.Label(
            top,
            text="XYRON ADMIN",
            bg=BG,
            fg=WHITE,
            font=("Arial", 25, "bold")
        ).pack(
            side="left"
        )

        tk.Button(
            top,
            text="REFRESH",
            command=self.load_scans,
            bg=PURPLE,
            fg="white",
            relief="flat",
            bd=0,
            padx=20,
            pady=7
        ).pack(
            side="right"
        )

        self.tree = ttk.Treeview(
            self.root,
            columns=(
                "id",
                "date",
                "license",
                "status",
                "detections"
            ),
            show="headings"
        )

        self.tree.heading(
            "id",
            text="ID"
        )

        self.tree.heading(
            "date",
            text="DATE"
        )

        self.tree.heading(
            "license",
            text="LICENSE"
        )

        self.tree.heading(
            "status",
            text="STATUS"
        )

        self.tree.heading(
            "detections",
            text="DETECTIONS"
        )

        self.tree.column(
            "id",
            width=50
        )

        self.tree.column(
            "date",
            width=170
        )

        self.tree.column(
            "license",
            width=180
        )

        self.tree.column(
            "status",
            width=100
        )

        self.tree.column(
            "detections",
            width=100
        )

        self.tree.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=10
        )

        self.tree.bind(
            "<Double-1>",
            self.show_scan
        )

        self.load_scans()


    def load_scans(self):

        try:

            response = requests.get(
                SERVER_URL + "/admin/scans",
                headers={
                    "Authorization":
                    "Bearer " + self.token
                },
                timeout=10
            )

            if response.status_code != 200:

                messagebox.showerror(
                    "Xyron",
                    "Could not load scans."
                )

                return

            data = response.json()

            for item in self.tree.get_children():
                self.tree.delete(item)

            for scan in data.get(
                "scans",
                []
            ):

                self.tree.insert(
                    "",
                    "end",
                    iid=str(scan["id"]),
                    values=(
                        scan["id"],
                        scan["created_at"],
                        scan["license_key"],
                        scan["status"],
                        scan["detections"]
                    )
                )

        except Exception:

            messagebox.showerror(
                "Xyron",
                "Server connection failed."
            )


    def show_scan(self, event):

        selected = self.tree.selection()

        if not selected:
            return

        scan_id = selected[0]

        try:

            response = requests.get(
                SERVER_URL + "/admin/scans",
                headers={
                    "Authorization":
                    "Bearer " + self.token
                },
                timeout=10
            )

            data = response.json()

            scan = None

            for item in data.get(
                "scans",
                []
            ):

                if str(item["id"]) == scan_id:
                    scan = item
                    break

            if not scan:
                return

            window = tk.Toplevel(
                self.root
            )

            window.title(
                "Xyron Scan Result"
            )

            window.geometry(
                "750x500"
            )

            window.configure(
                bg=BG
            )

            text = tk.Text(
                window,
                bg=PANEL,
                fg=WHITE,
                insertbackground=WHITE,
                relief="flat",
                font=("Consolas", 10)
            )

            text.pack(
                fill="both",
                expand=True,
                padx=15,
                pady=15
            )

            text.insert(
                "end",
                "XYRON SCAN RESULT\n"
            )

            text.insert(
                "end",
                "=================\n\n"
            )

            text.insert(
                "end",
                "ID: "
                + str(scan["id"])
                + "\n"
            )

            text.insert(
                "end",
                "DATE: "
                + scan["created_at"]
                + "\n"
            )

            text.insert(
                "end",
                "STATUS: "
                + scan["status"]
                + "\n"
            )

            text.insert(
                "end",
                "DETECTIONS: "
                + str(scan["detections"])
                + "\n\n"
            )

            for item in scan["results"]:

                text.insert(
                    "end",
                    "--------------------------------\n"
                )

                text.insert(
                    "end",
                    "NAME: "
                    + str(item.get("name"))
                    + "\n"
                )

                text.insert(
                    "end",
                    "TYPE: "
                    + str(item.get("type"))
                    + "\n"
                )

                text.insert(
                    "end",
                    "RISK: "
                    + str(item.get("risk"))
                    + "\n"
                )

                text.insert(
                    "end",
                    "SCORE: "
                    + str(item.get("score"))
                    + "\n"
                )

                text.insert(
                    "end",
                    "SHA256: "
                    + str(item.get("sha256"))
                    + "\n"
                )

                text.insert(
                    "end",
                    "EVIDENCE:\n"
                )

                for evidence in item.get(
                    "evidence",
                    []
                ):

                    text.insert(
                        "end",
                        "  - "
                        + str(evidence)
                        + "\n"
                    )

                text.insert(
                    "end",
                    "\n"
                )

            text.config(
                state="disabled"
            )

        except Exception:

            messagebox.showerror(
                "Xyron",
                "Could not load result."
            )


if __name__ == "__main__":

    root = tk.Tk()

    AdminPanel(root)

    root.mainloop()
