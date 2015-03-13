<?php

class Form_Select extends Form_Input
{
	protected $_values;
	protected $_value;

	public function __construct($name, $title, $value, array $values, $allowMultiple = false)
	{
		if ($allowMultiple) {
			$this->setAttribute('multiple', 'multiple');
			$name = $name . '[]';
		}

		parent::__construct($name, $title, null);

		$this->_value = $value;
		$this->_values = $values;
	}

	protected function _getInput()
	{
		$element = preg_replace('~^<input(.*)/>$~', 'select\1', parent::_getInput());

		$options = '';
		foreach ($this->_values as $value => $name) {
			$selected = (is_array($this->_value) && in_array($value, $this->_value) || $this->_value == $value);
			$options .= '<option value="'. htmlspecialchars($value) .'"'.($selected ? ' selected' : '').'>'. gettext($name) .'</option>';
		}

		return <<<EOT
	<{$element}>
		{$options}
	</select>
EOT;
	}
}
