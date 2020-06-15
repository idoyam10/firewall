import pathlib

RULES_FILE_PATH = str(pathlib.Path(__file__).parent.absolute()) + "\\config.txt"


class Rule:
    """each object represents a rule.

    agreed rule format: filter//'B'[or]'W'//[ip_list]//command

    rules_ls: list of all the rules object made.

    properties:
    filter: the bpf filter.
    ip_list: black or white list of ip addresses.
    is_white: True if the list is a whitelist.
    command: function to execute when filter is activated.
    """

    rules_ls = []  # list of all the objects created

    def __init__(self, rule_str, add_to_config):  # assuming rule_str is in the right format
        rule_ls = rule_str.split('//')
        self.filter = rule_ls[0]
        self.is_white = (rule_ls[1] == 'W')
        self.ip_list = rule_ls[2].split(',')
        self.command = int(rule_ls[3][0])

        Rule.rules_ls.append(self)
        if add_to_config:
            Rule.save_rule(self)

    def __str__(self):
        """return string of a rule at the agreed format"""

        is_white = 'B'
        if self.is_white:
            is_white = 'W'
        return "//".join([self.filter, is_white, self.ip_list, self.command])

    @staticmethod
    def check_rule(rule):
        """return True if the given str is in the agreed rule format. else False"""

        #  print("checking rule")
        rule_ls = rule.split('//')
        # print(rule_ls)

        if len(rule_ls) == 4:
            # print("passed 1")

            if type(rule_ls[0]) is str:
                # print("passed 2")

                if rule_ls[1] == 'B' or rule_ls[1] == 'W':
                    # print("passed 3")

                    try:
                        int(rule_ls[3])
                        # print("rule passed")
                        return True
                    except IndentationError:
                        return False
                    except ValueError:
                        return False

        return False

    @staticmethod
    def save_rule(rule):
        """adds rule to the config file."""

        f = open(RULES_FILE_PATH, 'r')
        lines = f.readlines()
        print("lines len before adding: "+str(len(lines)))
        f.close()

        lines.append((str(len(lines) + 1)).zfill(2) + ":" + str(rule) + "\n")
        lines.sort(key=lambda x: int(x[:2]))
        print("lines len after adding : " + str(len(lines)))
        open(RULES_FILE_PATH, 'w').close()

        f = open(RULES_FILE_PATH, 'w')
        f.writelines(line for line in lines)
        f.close()

    @staticmethod
    def config_into_rules():
        """creates rule objects out of all pre-loaded rules"""
        f = open(RULES_FILE_PATH, 'r')
        rules = f.readlines()
        for rule in rules:
            if Rule.check_rule(rule[3::]):
                Rule(rule[3::], False)
        print("pre loaded rules objects created:", len(Rule.rules_ls), '\n')

    @staticmethod
    def load_rules():
        """gets all rules from config, extracts the filter part and returns a joined BPF filter."""

        f = open(RULES_FILE_PATH, 'r')
        lines = f.readlines()
        # print(lines)
        f.close()

        rules_str_ls = [line[3::] for line in lines]  # list of all the rules as strings, unchecked
        # print(rules_str_ls)

        rules_filters_ls = []
        for rule_str in rules_str_ls:
            if Rule.check_rule(rule_str):  # if the rule is in the format
                rules_filters_ls.append(rule_str.split("//")[0])  # append filter

        rules_str = "(" + ') or ('.join(rules_filters_ls) + ")"
        # print("str of rules: " + rules_str)
        print("rules loaded!")
        print("--------------------------")
        return rules_str

