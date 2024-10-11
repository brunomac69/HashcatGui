import datetime
import re
import tkinter as tk
from tkinter import ttk, filedialog
import csv
#import paperclip

class HashcatCommandGenerator:
    def __init__(self, master):
        self.master = master
        master.title("Hashcat Command Generator")

        # Carregar algoritmos de um arquivo CSV
        self.algorithms = self.load_algorithms("algorithms.csv")
        self.masks= self.load_masks("masks.csv")
        self.parameters= self.load_parameters("parameters.csv")
        self.attacks=self.load_parameters("attacks.csv")


        # Algoritmo Combobox
        self.label_algoritm = tk.Label(master, text="Algorithm to use (-m):")
        self.label_algoritm.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        self.combo_algoritm = ttk.Combobox(master, values=self.algorithms)
        self.combo_algoritm.grid(row=0, column=1, columnspan=3, padx=10, pady=5, sticky=tk.EW)
        self.combo_algoritm.config(width=50)
        self.combo_algoritm["height"] = 30
        #search algoritm
         # Botão Add Rule ao lado
        
        self.btn_add_parameters = tk.Button(master, text="Filter", command=self.filter_algorithms)
        self.btn_add_parameters.grid(row=0, column=4, padx=5, pady=5,sticky=tk.W)


        # Ataque Combobox
        self.label_attack = tk.Label(master, text="Type of Attack (-a):")
        self.label_attack.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        self.combo_attack = ttk.Combobox(master, values=self.attacks)
        self.combo_attack.grid(row=1, column=1, columnspan=3, padx=10, pady=20,sticky=tk.EW)
        self.combo_attack.config(width=50)
        self.combo_attack["height"] = 40


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
        # Botão Add Rule ao lado
        self.btn_add_mask = tk.Button(master, text="Add Mask", command=self.add_mask)
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
       
        # Botão Add Rule ao lado
        self.btn_add_rule = tk.Button(master, text="Add Rule", command=self.add_rule)
        self.btn_add_rule.grid(row=6, column=4, padx=5, pady=5,sticky=tk.W)
        

        # Output File
        self.label_output = tk.Label(master, text="Output File (-o):")
        self.label_output.grid(row=7, column=0, padx=10, pady=5, sticky=tk.W)
        self.entry_output = tk.Entry(master, width=30)
        self.entry_output.grid(row=7, column=1, padx=10, pady=5,sticky=tk.EW)
        self.btn_browse_output = tk.Button(master, text="Browse", command=lambda: self.browse_file(self.entry_output))
        self.btn_browse_output.grid(row=7, column=2, padx=10, pady=5)
        self.btn_default_output = tk.Button(master, text="Default", command=self.default_output)
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
        # Botão Add Rule ao lado
        self.btn_add_parameters = tk.Button(master, text="Add", command=self.add_parameters)
        self.btn_add_parameters.grid(row=8, column=4, padx=5, pady=5,sticky=tk.W)


        # Sessão (--session)
        self.label_session = tk.Label(master, text="Session (--session):")
        self.label_session.grid(row=9, column=0, padx=10, pady=5, sticky=tk.W)
        self.entry_session = tk.Entry(master, width=30)
        self.entry_session.grid(row=9, column=1, padx=10, pady=5, sticky=tk.EW)
               
        self.btn_browse_output = tk.Button(master, text="Default", command=self.default_session)
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


        # Botão para gerar comando
        self.btn_generate = tk.Button(master, text="Generate Command", command=self.generate_command)
        self.btn_generate.grid(row=11, column=0, columnspan=4, padx=10, pady=20)

        # Textbox para mostrar comando gerado
        self.text_output = tk.Text(master, height=5, width=80)
        self.text_output.grid(row=12, column=0, columnspan=5, padx=10, pady=5)

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
    def filter_algorithms(self):
        search_term = self.combo_algoritm.get()
        filtered_algorithms = [alg for alg in self.algorithms if search_term.lower() in alg.lower()]
        self.combo_algoritm['values'] = filtered_algorithms

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
        entry_field.delete(0, tk.END)
        entry_field.insert(0, file_path)
    
    #função para remover mais que dois espaços.
    def trim_spaces(self, text):  
            return re.sub(r'\s{2,}', ' ', text)
    
    # Função para gravar o histórico de comandos
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

if __name__ == "__main__":
    root = tk.Tk()
    root.grid_columnconfigure(0, weight=0) #não expande
    root.grid_columnconfigure(1, weight=1) #expande
    root.grid_columnconfigure(2, weight=0) #nao expande
    root.grid_columnconfigure(3, weight=1) #expande
    app = HashcatCommandGenerator(root)
    root.mainloop()
