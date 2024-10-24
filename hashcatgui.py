import datetime
import json
import os
import re
import tkinter as tk
from tkinter import END, ttk, filedialog
import csv
import platform
import subprocess
#import paperclip

class HashcatCommandGenerator:
    def __init__(self, master):
        self.master = master
        master.title("Hashcat Command Generator")

        # Close window event to save defaults.json
        master.protocol("WM_DELETE_WINDOW", self.on_closing)


        # Carregar algoritmos de um arquivo CSV
        self.algorithms = self.load_algorithms("algorithms.csv")
        self.masks= self.load_masks("masks.csv")
        self.parameters= self.load_parameters("parameters.csv")
        self.attacks=self.load_parameters("attacks.csv")
        self.utils=self.load_utils("utils.csv")


        # Algoritmo Combobox
        self.label_algoritm = tk.Label(master, text="Algorithm to use (-m):")
        self.label_algoritm.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        self.combo_algoritm = ttk.Combobox(master, values=self.algorithms)
        self.combo_algoritm.grid(row=0, column=1, columnspan=3, padx=10, pady=5, sticky=tk.EW)
        self.combo_algoritm.config(width=50)
        self.combo_algoritm["height"] = 30
        self.combo_algoritm.bind("<<ComboboxSelected>>", self.set_help)
        self.combo_algoritm.bind("<Return>", self.filter_algorithms) #activate event key enter/return
        
        #Search algoritm
        self.btn_filter_algoritms = tk.Button(master, text="Filter", command=lambda: self.filter_algorithms(""))
        self.btn_filter_algoritms.grid(row=0, column=4, padx=5, pady=5,sticky=tk.W)

        # Ataque Combobox
        self.label_attack = tk.Label(master, text="Type of Attack (-a):")
        self.label_attack.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        self.combo_attack = ttk.Combobox(master, values=self.attacks)
        self.combo_attack.grid(row=1, column=1, columnspan=3, padx=10, pady=20,sticky=tk.EW)
        self.combo_attack.config(width=50)
        self.combo_attack["height"] = 40
        self.combo_attack.bind("<<ComboboxSelected>>", self.set_help)

        # Hash or File
        self.label_hash = tk.Label(master, text="Hash or File:")
        self.label_hash.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        self.entry_hash = tk.Entry(master, width=30)
        self.entry_hash.grid(row=2, column=1, padx=10, pady=5, sticky=tk.EW)
        self.btn_browse_hash = tk.Button(master, text="Browse", command=lambda: self.browse_file(self.entry_hash))
        self.btn_browse_hash.grid(row=2, column=2, padx=10, pady=5)
            # help for Hash
        self.label_wordlist1_help = tk.Label(master, text="Hash File ~/tst.hash or Hash:938c2cc0dc...")
        self.label_wordlist1_help.grid(row=2, column=3, padx=5, pady=5, sticky=tk.EW)


        # Wordlist 1 or Mask
        self.label_wordlist1 = tk.Label(master, text="Wordlist 1 or Mask:")
        self.label_wordlist1.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
        self.entry_wordlist1 = tk.Entry(master, width=30)
        self.entry_wordlist1.grid(row=3, column=1, padx=10, pady=5, sticky=tk.EW)
        self.btn_browse_wordlist1 = tk.Button(master, text="Browse", command=lambda: self.browse_file(self.entry_wordlist1))
        self.btn_browse_wordlist1.grid(row=3, column=2, padx=10, pady=5)

        # Combobox e botão Browse lado a lado
        self.combo_mask = ttk.Combobox(master, values=self.load_rules("masks.csv"))
        self.combo_mask.grid(row=3, column=3, padx=5, pady=0, sticky=tk.EW)
        self.combo_mask["height"] = 20
        self.combo_mask.bind("<<ComboboxSelected>>", self.set_help)
        # Botão Add Rule ao lado
        self.btn_add_mask = tk.Button(master, text="Add", command=self.add_mask)
        self.btn_add_mask.grid(row=3, column=4, padx=5, pady=5,sticky=tk.W)
        

        # Wordlist 2
        self.label_wordlist2 = tk.Label(master, text="Wordlist 2:")
        self.label_wordlist2.grid(row=4, column=0, padx=10, pady=5, sticky=tk.W)
        self.entry_wordlist2 = tk.Entry(master, width=30)
        self.entry_wordlist2.grid(row=4, column=1, padx=10, pady=5, sticky=tk.EW)
        self.btn_browse_wordlist2 = tk.Button(master, text="Browse", command=lambda: self.browse_file(self.entry_wordlist2))
        self.btn_browse_wordlist2.grid(row=4, column=2, padx=10, pady=5)

        # Wordlist 3
        self.label_wordlist3 = tk.Label(master, text="Wordlist 3:")
        self.label_wordlist3.grid(row=5, column=0, padx=10, pady=5, sticky=tk.W)
        self.entry_wordlist3 = tk.Entry(master, width=30)
        self.entry_wordlist3.grid(row=5, column=1, padx=10, pady=5, sticky=tk.EW)
        self.btn_browse_wordlist3 = tk.Button(master, text="Browse", command=lambda: self.browse_file(self.entry_wordlist3))
        self.btn_browse_wordlist3.grid(row=5, column=2, padx=10, pady=5)

       # Regras (-r)
        self.label_rules = tk.Label(master, text="Rules (-r):")
        self.label_rules.grid(row=6, column=0, padx=10, pady=5, sticky=tk.W)
        self.entry_rules = tk.Entry(master, width=30)
        self.entry_rules.grid(row=6, column=1, padx=10, pady=5, sticky=tk.EW)

        self.btn_browse_rules = tk.Button(master, text="Browse", command=lambda: self.browse_file(self.entry_rules))
        self.btn_browse_rules.grid(row=6, column=2, padx=5, pady=5)

        # Combobox e botão Browse lado a lado
        self.combo_rules = ttk.Combobox(master, values=self.load_rules("rules.csv"))
        self.combo_rules.grid(row=6, column=3, padx=5, pady=0, sticky=tk.EW)
        self.combo_rules["height"] = 20
        self.combo_rules.bind("<<ComboboxSelected>>", self.set_help)
       
        # Botão Add Rule ao lado
        self.btn_add_rule = tk.Button(master, text="Add Rule", command=lambda: self.add_rule())
        self.btn_add_rule.grid(row=6, column=4, padx=5, pady=5,sticky=tk.W)
        

        # Output File
        self.label_output = tk.Label(master, text="Output File (-o):")
        self.label_output.grid(row=7, column=0, padx=10, pady=5, sticky=tk.W)
        self.entry_output = tk.Entry(master, width=30)
        self.entry_output.grid(row=7, column=1, padx=10, pady=5,sticky=tk.EW)
        self.btn_browse_output = tk.Button(master, text="Browse", command=lambda: self.browse_file(self.entry_output))
        self.btn_browse_output.grid(row=7, column=2, padx=10, pady=5)
        self.btn_default_output = tk.Button(master, text="Default", command=lambda: self.default_output())
        self.btn_default_output.grid(row=7, column=3, padx=10, pady=5, sticky=tk.W)

        #Other Parameters
        # Parameters or HELP
        self.label_parameters = tk.Label(master, text="Other Parameters:")
        self.label_parameters.grid(row=8, column=0, padx=10, pady=5, sticky=tk.W)
        self.entry_parameters = tk.Entry(master, width=30)
        self.entry_parameters.grid(row=8, column=1, padx=10, pady=5, sticky=tk.EW)

        # Combobox e botão Browse lado a lado
        self.combo_parameters = ttk.Combobox(master, values=self.parameters)
        self.combo_parameters.grid(row=8, column=3, padx=5, pady=0, sticky=tk.EW)
        self.combo_parameters["height"] = 20
        self.combo_parameters.bind("<<ComboboxSelected>>", self.set_help)
        
        # Botão Add Rule ao lado
        self.btn_add_parameters = tk.Button(master, text="Add", command=lambda: self.add_parameters())
        self.btn_add_parameters.grid(row=8, column=4, padx=5, pady=5,sticky=tk.W)


        # Sessão (--session)
        self.label_session = tk.Label(master, text="Session (--session):")
        self.label_session.grid(row=9, column=0, padx=10, pady=5, sticky=tk.W)
        self.entry_session = tk.Entry(master, width=30)
        self.entry_session.grid(row=9, column=1, padx=10, pady=5, sticky=tk.EW)
               
        self.btn_browse_output = tk.Button(master, text="Default", command= lambda: self.default_session())
        self.btn_browse_output.grid(row=9, column=2, padx=10, pady=5)

        # Checkboxes
        self.var_force = tk.IntVar()
        self.var_gpu = tk.IntVar()
        self.var_stdout = tk.IntVar()
        self.var_guess = tk.IntVar()

        self.chk_force = tk.Checkbutton(master, text="--force", variable=self.var_force)
        self.chk_force.grid(row=10, column=0, padx=10, pady=5, sticky=tk.W)

        self.chk_gpu = tk.Checkbutton(master, text="--gpu-temp-disable", variable=self.var_gpu)
        self.chk_gpu.grid(row=10, column=1, padx=10, pady=5, sticky=tk.W)
        
        self.chk_stdout = tk.Checkbutton(master, text="--stdout", variable=self.var_stdout)
        self.chk_stdout.grid(row=10, column=2, padx=10, pady=5, sticky=tk.W)

        self.chk_guess = tk.Checkbutton(master, text="--keep-guessing", variable=self.var_guess)
        self.chk_guess.grid(row=10, column=3, padx=10, pady=5, sticky=tk.W)

        # HASH UTILS Combobox
        self.label_utils = tk.Label(master, text="HASHCAT- UTILS/PROCESSOR's:")
        self.label_utils.grid(row=11, column=0, padx=10, pady=5, sticky=tk.W)
        self.combo_utils = ttk.Combobox(master, values=self.utils)
        self.combo_utils.grid(row=11, column=1, columnspan=3, padx=10, pady=5, sticky=tk.EW)
        self.combo_utils.config(width=50)
        self.combo_utils["height"] = 30
        self.combo_utils.bind("<<ComboboxSelected>>", self.set_utils)
        self.combo_utils.bind("<Return>", self.filter_utils)

         #Search algoritm
        self.btn_filter_utils = tk.Button(master, text="Filter", command=lambda: self.filter_utils(""))
        self.btn_filter_utils.grid(row=11, column=4, padx=5, pady=5,sticky=tk.W)

        # Botão para gerar comando
        self.btn_generate = tk.Button(master, text="  Generate Hashcat Command  ", bg="light green", command=lambda: self.generate_command())
        self.btn_generate.grid(row=12, column=0, columnspan=3, padx=10, pady=20, sticky=tk.E)

        # Botão para limpar comando
        self.btn_execute_console = tk.Button(master, text="Execute Command", bg="light salmon", command=lambda: self.execute_command(""))
        self.btn_execute_console.grid(row=12, column=3, columnspan=1, padx=10, pady=20, sticky=tk.W)

         # Botão para limpar comando
        self.btn_clear = tk.Button(master, text="Clear Command", command=lambda: self.clear_controls())
        self.btn_clear.grid(row=12, column=3, columnspan=1, padx=10, pady=20, sticky=tk.E)
        
         # Botão history
        self.btn_history = tk.Button(master, text="History", command=lambda: self.open_file("command_history.txt"))
        self.btn_history.grid(row=12, column=4, padx=5, pady=20, sticky=tk.W)

        # Textbox para mostrar comando gerado
        self.text_output = tk.Text(master, height=5, width=80)
        self.text_output.grid(row=13, column=0, columnspan=5, padx=10, pady=5)

         # HELP 
        self.label_help_text = tk.Label(master, text="HELP TEXT")
        self.label_help_text.grid(row=14, column=0, columnspan=5, padx=10, pady=5, sticky=tk.W)

        self.load_defaults()

    def open_file(self, file_name):
        script_dir= os.path.dirname(os.path.realpath(__file__))
        file_path= os.path.join(script_dir,file_name)
        if file_path:
            os.startfile(file_path)

     # Carregar algoritmos de um arquivo CSV
    def load_attacks(self, filename):
        algorithms = []
        with open(filename, 'r', encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                if row:
                    algorithms.append(row[0])
        return algorithms

    # Carregar algoritmos de um arquivo CSV
    def load_algorithms(self, filename):
        algorithms = []
        with open(filename, 'r', encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                if row:
                    algorithms.append(row[0])
        return algorithms
    
    # Função para filtrar os algoritmos
    def filter_algorithms(self, event):
        search_term = self.combo_algoritm.get()
        filtered_algorithms = [alg for alg in self.algorithms if search_term.lower() in alg.lower()]
        self.combo_algoritm['values'] = filtered_algorithms

    # Função para filtrar os algoritmos
    def filter_utils(self, event):
        search_term = self.combo_utils.get()
        filtered_utils = [alg for alg in self.utils if search_term.lower() in alg.lower()]
        self.combo_utils['values'] = filtered_utils

    # Carregar regras de um arquivo CSV
    def load_rules(self, filename):
        rules = []
        with open(filename, 'r',  encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                if row:
                    rules.append(row[0])
        return rules

    # Carregar masks de um arquivo CSV
    def load_masks(self, filename):
        masks = []
        with open(filename, 'r', encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                if row: #verifica se está vazia'
                    masks.append(row[0])
        return masks
    
    # Carregar parameters de um arquivo CSV
    def load_parameters(self, filename):
        algorithms = []
        with open(filename, 'r', encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                if row:
                    algorithms.append(row[0])
        return algorithms

    # Carregar parameters de um arquivo CSV
    def load_utils(self, filename):
        utils = []
        with open(filename, 'r', encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                if row:
                    utils.append(row[0])
        return utils
    
    #Set Help Text
    def set_help(self, event):
        widget = event.widget
        selected_value = widget.get()  # Obter o valor selecionado
        #self.label_help_text.delete(0, tk.END)
        self.label_help_text.config(text="help: " + selected_value)

    # Adicionar parameters ao campo de worlist1
    def add_parameters(self):
        selected_parameters = self.combo_parameters.get().split(";")[0]
        current_parameters = self.entry_parameters.get()
        new_parameters = current_parameters + " " + selected_parameters if current_parameters else selected_parameters
        self.entry_parameters.delete(0, tk.END)
        self.entry_parameters.insert(0, new_parameters)


    # Adicionar mask ao campo de worlist1
    def add_mask(self):
        selected_mask = self.combo_mask.get().split(";")[0]
        current_mask = self.entry_wordlist1.get()
        new_rules = current_mask + selected_mask if current_mask else selected_mask
        self.entry_wordlist1.delete(0, tk.END)
        self.entry_wordlist1.insert(0, new_rules)


    # Adicionar regra ao campo de regras
    def add_rule(self):
        selected_rule = self.combo_rules.get().split(";")[0]
        #One Rule
        new_rules = selected_rule
        #multiple rules:
        #current_rules = self.entry_rules.get()
        #new_rules = current_rules + " " + selected_rule if current_rules else selected_rule
        
        self.entry_rules.delete(0, tk.END)
        self.entry_rules.insert(0, new_rules)

    # Função para buscar caminho do arquivo
    def browse_file(self, entry_field):
        file_path = filedialog.askopenfilename()
        file_path = self.quote_spaces_paths(file_path) #Quote string paths if have spaces.
        entry_field.delete(0, tk.END)
        entry_field.insert(0, file_path)
    
    #Remove 2 or more spaces from command text
    def trim_spaces(self, text):  
            return re.sub(r'\s{2,}', ' ', text)
    
    #tQuote string paths if have spaces"""
    def quote_spaces_paths(self, string):  
        if ' ' in string:
            return f'"{string}"'
        return string
    
    # Save Command history
    def write_command_to_history(self, command):
        with open("command_history.txt", "a") as file:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            file.write(f"{timestamp} - {command}\n")

    def default_session(self):
        default=datetime.datetime.now().strftime("%Y%m%d%H%M")
        self.entry_session.delete(0, tk.END)
        self.entry_session.insert(tk.END, default)

    def default_output(self):
        default="crack.txt"
        self.entry_output.delete(0, tk.END)
        self.entry_output.insert(tk.END, default)

    def clear_controls(self):
        self.entry_hash.delete(0, tk.END)
        self.entry_wordlist1.delete(0, tk.END)
        self.entry_wordlist2.delete(0, tk.END)
        self.entry_wordlist3.delete(0, tk.END)
        self.entry_rules.delete(0, tk.END)
        self.entry_output.delete(0, tk.END)
        self.entry_parameters.delete(0, tk.END)
        self.entry_session.delete(0, tk.END)
        self.chk_force.deselect
        self.chk_gpu.deselect
        self.chk_stdout.deselect
        self.chk_guess.deselect
        self.combo_algoritm.set("")
        self.combo_attack.set("")

    #Set Hashcat Utils and Processors
    def set_utils(self, event):
        widget = event.widget
        selected_value = widget.get()  # Obter o valor selecionado
        #self.label_help_text.delete(0, tk.END)
        
        if ";" in selected_value:
            help_text=selected_value.split(";")[1]
        else:help_text=selected_value
        self.label_help_text.config(text="help: " + help_text)

        #get replacement params
        alg = self.combo_algoritm.get()
        attack = self.combo_attack.get()
        hash_file = self.entry_hash.get()
        wordlist1 = self.entry_wordlist1.get()
        wordlist2 = self.entry_wordlist2.get()
        wordlist3 = self.entry_wordlist3.get()
        rules = self.entry_rules.get()
        output = self.entry_output.get()

        if alg: alg="-m " + alg.split(";")[0]
        if attack: attack= attack.split(";")[0] #prefixo -a já está na combobox
        if rules: rules= "-r " + rules
        if output: output= "-o " + output

        
        command= self.combo_utils.get()
        command= command.split(";")[0]

        if "{alg}" in command:
            command = command.replace("{alg}", alg)
        if "{attack}" in command:
            command = command.replace("{attack}", attack)
        if "{hash}" in command:
            command = command.replace("{hash}", hash_file)
        if "{wl1}" in command:
            command = command.replace("{wl1}", wordlist1)
        if "{wl2}" in command:
            command = command.replace("{wl2}", wordlist2)
        if "{wl3}" in command:
            command = command.replace("{wl3}", wordlist3)
        if "{rules}" in command:
            command = command.replace("{rules}", rules)
        if "{output}" in command:
            command = command.replace("{output}", output)

         # Exibir o comando gerado no textbox
        self.text_output.delete(1.0, tk.END)
        self.text_output.insert(tk.END, command)

        # Gravar no histórico
        self.write_command_to_history(command)


    # Função para gerar comando hashcat
    def generate_command(self):
        alg = self.combo_algoritm.get()
        attack = self.combo_attack.get()
        hash_file = self.entry_hash.get()
        wordlist1 = self.entry_wordlist1.get()
        wordlist2 = self.entry_wordlist2.get()
        wordlist3 = self.entry_wordlist3.get()
        rules = self.entry_rules.get()
        output = self.entry_output.get()
        session = self.entry_session.get()
        parameters = self.entry_parameters.get()
        
        # Checkboxes
        force_flag = '--force' if self.var_force.get() else ''
        gpu_flag = '--gpu-temp-disable' if self.var_gpu.get() else ''
        keep_guessing_flag = '--keep-guessing' if self.var_guess.get() else ''
        stdout_flag = '--stdout' if self.var_stdout.get() else ''

        if alg: alg="-m " + alg.split(";")[0]
        if attack: attack= attack.split(";")[0] #prefixo -a já está na combobox
        if rules: rules= "-r " + rules
        if output: output= "-o " + output


        # Montar o comando
        command = f"hashcat {alg} {attack} {hash_file} {wordlist1} {wordlist2} {wordlist3} {rules} {output} {session} {force_flag} {gpu_flag} {keep_guessing_flag} {parameters} "
        
        if stdout_flag:
            command = f"hashcat {attack} {wordlist1} {wordlist2} {wordlist3} {rules} {output} {session} {force_flag} {gpu_flag} {keep_guessing_flag} {parameters} {stdout_flag}"
   
        command = self.trim_spaces(command)

        # Exibir o comando gerado no textbox
        self.text_output.delete(1.0, tk.END)
        self.text_output.insert(tk.END, command)

        # Gravar no histórico
        self.write_command_to_history(command)
        #try:
        #    pyperclip.copy(command)
        #except Exception as e:
        #    self.write_command_to_history(f"ERROR: Copy to clipboard: {e}")

    def on_closing(self):
            # Salvando os valores atuais antes de fechar
            self.save_defaults()
            root.destroy()

    def save_defaults(self):
        # Obter valores de widgets
        values = {
            'algoritm': self.combo_algoritm.get(),
            'attack': self.combo_attack.get(),
            'hash_file': self.entry_hash.get(),
            'wordlist1': self.entry_wordlist1.get(),
            'wordlist2': self.entry_wordlist2.get(),
            'wordlist3': self.entry_wordlist3.get(),
            'rules': self.entry_rules.get(),
            'output': self.entry_output.get(),
            'parameters': self.entry_parameters.get(),
            'session': self.entry_session.get(),
            'force': self.var_force.get(),
            'gpu': self.var_gpu.get(),
            'stdout': self.var_stdout.get(),
            'guess': self.var_guess.get(),
        }

        # Salvar no arquivo JSON
        with open("defaults.json", "w") as f:
            json.dump(values, f)

    def load_defaults(self):
        if os.path.exists("defaults.json"):
            with open("defaults.json", "r") as f:
                values = json.load(f)
                self.combo_algoritm.set(values.get('algoritm', ''))
                self.combo_attack.set(values.get('attack', ''))
                self.entry_hash.insert(0, values.get('hash_file', ''))
                self.entry_wordlist1.insert(0, values.get('wordlist1', ''))
                self.entry_wordlist2.insert(0, values.get('wordlist2', ''))
                self.entry_wordlist3.insert(0, values.get('wordlist3', ''))
                self.entry_rules.insert(0, values.get('rules', ''))
                self.entry_output.insert(0, values.get('output', ''))
                self.entry_parameters.insert(0, values.get('parameters', ''))
                self.entry_session.insert(0, values.get('session', ''))
                self.var_force.set(values.get('force', 0))
                self.var_gpu.set(values.get('gpu', 0))
                self.var_stdout.set(values.get('stdout', 0))
                self.var_guess.set(values.get('guess', 0))


    def execute_command(self, command_text):
        if not command_text:
            command_text = self.text_output.get("1.0", END).strip()
        
        if command_text:
            # Detectar o sistema operacional
            if platform.system() == "Windows":
                # Windows: Executa o comando no Prompt de Comando em uma nova janela
                subprocess.Popen(['cmd', '/c', 'start', 'cmd', '/k', command_text])  # Abre nova janela e executa
            else:
                # Linux ou Mac: Abre o terminal e executa o comando em uma nova janela
                # Testar para diferentes terminais (gnome-terminal, konsole, xfce4-terminal)
                subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'{command_text}; exec bash'])  # Nova janela sem bloquear


if __name__ == "__main__":
    root = tk.Tk()
    root.grid_columnconfigure(0, weight=0) #não expande
    root.grid_columnconfigure(1, weight=1) #expande
    root.grid_columnconfigure(2, weight=0) #nao expande
    root.grid_columnconfigure(3, weight=1) #expande
    app = HashcatCommandGenerator(root)
    root.mainloop()
