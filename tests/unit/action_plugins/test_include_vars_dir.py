from ansible.compat.tests import unittest
from ansible.compat.tests.mock import patch, MagicMock, mock_open

from ansible.errors import AnsibleError
from ansible.playbook.play_context import PlayContext
from ansible.plugins import PluginLoader

from ansible.parsing.dataloader import DataLoader
from action_plugins.include_vars_dir import ActionModule
import os


class TestIncludeVarsDirPlugin(unittest.TestCase):

    def test_foo(self):
        mock_task = MagicMock()
        mock_task.action = "include_vars_dir"
        base_path = (
            os.path.realpath(os.path.dirname(os.path.realpath(__file__)))
        )
        vars_dir = os.path.join(base_path, "fixtures/vars")
        mock_task.args = dict(dir=vars_dir,depth=9,name='foobar')
        mock_connection = MagicMock()
        play_context = PlayContext()
        mock_task.async = None
        loader = DataLoader()
        action_base = (
            ActionModule(
                mock_task, mock_connection, play_context, loader, None, None
            )
        )
        action_base._task._role = None
        results = action_base.run()
        print results

def main():
    unittest.main()

if __name__ == '__main__':
    main()
