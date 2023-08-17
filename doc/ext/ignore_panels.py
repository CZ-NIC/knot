from docutils.parsers.rst import Directive

class IgnorePanels(Directive):

    has_content = True

    def run(self):
        return list()

def setup(app):

    app.add_directive("panels", IgnorePanels)

    return {
        'version': '0.1',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
